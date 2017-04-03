# frozen_string_literal: true

require './app/models/rapid_connect_service'

describe RapidConnectService, type: :model do
  def stringify_keys(hash)
    hash.reduce({}) { |a, (k, v)| a.merge(k.to_s => v) }
  end

  let(:attrs) { stringify_keys(attributes_for(:rapid_connect_service)) }
  let(:json) { attrs.to_json }
  let(:redis) { Redis.new }

  subject { build(:rapid_connect_service, attrs) }

  context 'validations' do
    it { is_expected.to validate_presence_of(:name) }
    it { is_expected.to validate_presence_of(:organisation) }
    it { is_expected.to validate_presence_of(:registrant_name) }
    it { is_expected.to validate_presence_of(:registrant_mail) }

    it { is_expected.to validate_presence_of(:secret) }
    it { is_expected.to validate_length_of(:secret).is_at_least(16) }

    it { is_expected.to validate_presence_of(:audience) }
    it { is_expected.to allow_value('http://example.com').for(:audience) }
    it { is_expected.to allow_value('https://example.com').for(:audience) }
    it { is_expected.not_to allow_value('https://a b.x.com').for(:audience) }
    it { is_expected.not_to allow_value('example.com').for(:audience) }

    it { is_expected.to validate_presence_of(:endpoint) }
    it { is_expected.to allow_value('http://example.com').for(:endpoint) }
    it { is_expected.to allow_value('https://example.com').for(:endpoint) }
    it { is_expected.not_to allow_value('https://a b.x.com').for(:endpoint) }
    it { is_expected.not_to allow_value('example.com').for(:endpoint) }

    it { is_expected.to allow_value('research').for(:type) }
    it { is_expected.to allow_value('auresearch').for(:type) }
    it { is_expected.to allow_value('zendesk').for(:type) }
    it { is_expected.to allow_value('freshdesk').for(:type) }
    it { is_expected.not_to allow_value('invalid').for(:type) }

    it { is_expected.to validate_numericality_of(:created_at).allow_nil }
  end

  context '#identifier!' do
    let(:identifier) { '1' }
    before do
      allow(SecureRandom).to receive(:urlsafe_base64).and_return(identifier)
    end

    it 'returns the identifier' do
      expect(subject.identifier!).to eq(identifier)
    end

    it 'persists the identifier' do
      subject.identifier!
      expect(subject.identifier).to eq(identifier)
    end

    it 'leaves an existing identifier' do
      subject.identifier = '2'
      subject.identifier!
      expect(subject.identifier).to eq('2')
    end

    it 'returns the existing identifier' do
      subject.identifier = '2'
      expect(subject.identifier!).to eq('2')
    end
  end

  context '#to_s' do
    let(:attrs) do
      attrs = attributes_for(:rapid_connect_service,
                             name: 'Test', identifier: 'xyz')
      stringify_keys(attrs)
    end

    it 'generates a string' do
      expect(subject.to_s).to eq('RapidService(identifier=xyz name=`Test`)')
    end

    it 'generates a string when identifier is nil' do
      attrs['identifier'] = nil
      expect(subject.to_s).to eq('RapidService(identifier=nil name=`Test`)')
    end
  end

  context '#to_json' do
    it 'creates valid json' do
      expect { JSON.parse(subject.to_json) }.not_to raise_error
    end

    it 'contains the attributes' do
      expect(JSON.parse(subject.to_json)).to eq(attrs)
    end
  end

  context '#from_json' do
    subject { RapidConnectService.new.from_json(json) }

    it 'sets the attributes map' do
      expect(subject).to have_attributes(attrs)
    end

    it 'sets the attribute accessors' do
      attrs.each do |k, v|
        expect(subject.send(k.to_sym)).to eq(v)
      end
    end

    it 'fails on an invalid attribute' do
      bad_data = attrs.merge('unknown_attribute' => 'value').to_json
      expect { RapidConnectService.new.from_json(bad_data) }
        .to raise_error(/Bad attribute/)
    end

    # This checks compatibility with the format used by Rapid Connect up to
    # version 1.0.1 (and likely beyond).
    #
    # If the data format changes in the future, backward compatibility will
    # still need to be maintained, so don't change this unless you know what
    # you're doing.
    context 'backward compatibility' do
      let(:attrs) do
        {
          'organisation' => 'Test Organisation',
          'name' => 'test service',
          'audience' => 'https://example.com',
          'endpoint' => 'http://example.com/auth/jwt',
          'secret' => 'abcdABCD1234!@#$%^&*()',
          'registrant_name' => 'John Doe',
          'registrant_mail' => 'j.doe@example.com',
          'enabled' => true
        }
      end

      it 'sets the attributes map' do
        expect(subject).to have_attributes(attrs)
      end

      it 'sets the attribute accessors' do
        attrs.each do |k, v|
          expect(subject.send(k.to_sym)).to eq(v)
        end
      end

      it 'considers legacy data valid' do
        expect(subject).to be_valid
      end

      it 'defaults to "research" type' do
        expect(subject.type).to eq('research')
      end

      it 'updates the serialized data' do
        new_attrs = JSON.parse(subject.to_json)
        expect(new_attrs.delete('type')).to eq('research')
        expect(new_attrs).to eq(attrs)
      end
    end
  end
end

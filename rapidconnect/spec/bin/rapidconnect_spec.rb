# frozen_string_literal: true

load './bin/rapidconnect'

describe RapidConnectCLI do
  describe 'register' do
    let(:args) do
      [].tap do |result|
        result << id
        result << '--name' << name if name
        result << '--admin' << admin if admin
        result << '--mail' << mail if mail
        result << '--org' << org if org
        result << '--aud' << aud if aud
        result << '--url' << url if url
        result << '--type' << type if type
        result << '--secret' << secret if secret
      end
    end

    let(:attrs) do
      attributes_for(:rapid_connect_service)
        .slice(:audience, :endpoint, :secret, :type, :name,
               :organisation, :registrant_name, :registrant_mail)
    end

    let(:id) { SecureRandom.urlsafe_base64 }
    let(:aud) { attrs[:audience] }
    let(:url) { attrs[:endpoint] }
    let(:secret) { attrs[:secret] }
    let(:type) { attrs[:type] }
    let(:name) { attrs[:name] }
    let(:admin) { attrs[:registrant_name] }
    let(:mail) { attrs[:registrant_mail] }
    let(:org) { attrs[:organisation] }

    let(:redis) { Redis.new }

    def run
      described_class.start(['register', *args])
    end

    subject do
      lambda do
        old = $stderr
        begin
          $stderr = StringIO.new
          run
        ensure
          $stderr = old
        end
      end
    end

    def saved_attributes
      raw = redis.hget('serviceproviders', id)
      JSON.parse(raw, symbolize_names: true)
    end

    def service
      RapidConnectService.new.tap { |o| o.attributes = saved_attributes }
    end

    def service_count
      redis.hlen('serviceproviders')
    end

    context 'for a new registration' do
      it 'increments service count' do
        expect { run }.to change(self, :service_count).by(1)
      end

      it 'sets the attributes' do
        subject.call
        expect(service).to have_attributes(attrs)
      end

      it 'sets the created_at timestamp' do
        Timecop.freeze do
          subject.call
          expect(service.created_at).to eq(Time.now.utc.to_i)
        end
      end

      it 'enables the new service' do
        subject.call
        expect(service.enabled).to be_truthy
      end

      context 'output' do
        subject { -> { run } }

        it 'indicates successful creation' do
          expect { run }.to output(/Registered new service/).to_stderr
        end
      end

      shared_context 'failed creation' do |field:|
        it 'fails to create' do
          expect { run }.to raise_error(SystemExit)
            .and not_change(self, :service_count)
            .and output(/#{field} can't be blank/).to_stderr
        end
      end

      context 'with a missing name option' do
        let(:name) { nil }
        include_context 'failed creation', field: 'Name'
      end

      context 'with a missing org option' do
        let(:org) { nil }
        include_context 'failed creation', field: 'Organisation'
      end

      context 'with a missing admin option' do
        let(:admin) { nil }
        include_context 'failed creation', field: 'Registrant name'
      end

      context 'with a missing mail option' do
        let(:mail) { nil }
        include_context 'failed creation', field: 'Registrant mail'
      end

      context 'with a missing aud option' do
        let(:aud) { nil }
        include_context 'failed creation', field: 'Audience'
      end

      context 'with a missing url option' do
        let(:url) { nil }
        include_context 'failed creation', field: 'Endpoint'
      end

      context 'with a missing type option' do
        let(:type) { nil }

        it 'increments service count' do
          expect { run }.to change(self, :service_count).by(1)
        end

        it 'sets the type to "research"' do
          subject.call
          expect(service.type).to eq('research')
        end
      end

      context 'with a missing secret option' do
        let(:secret) { nil }
        include_context 'failed creation', field: 'Secret'
      end
    end

    context 'when the service already exists' do
      let!(:existing) do
        create(:rapid_connect_service, created_at: 1.year.ago.utc.to_i)
      end

      let(:id) { existing.identifier }

      it 'updates the attributes' do
        expect { run }.to change(self, :saved_attributes).to include(attrs)
      end

      it 'does not update the created_at timestamp' do
        expect { run }.not_to(change { service.created_at })
      end

      context 'existing service is disabled' do
        let!(:existing) do
          create(:rapid_connect_service, created_at: 1.year.ago.utc.to_i,
                                         enabled: false)
        end

        it 'enables the existing service' do
          expect { run }.to change { service.enabled }.to be_truthy
        end
      end

      context 'output' do
        it 'indicates successful creation' do
          expect { run }.to output(/Updated service registration/).to_stderr
        end
      end

      shared_context 'leave attribute intact' do |attr:|
        it 'leaves the existing value intact' do
          expect { run }.not_to(change { service.attributes[attr.to_s] })
        end
      end

      context 'with a missing name option' do
        let(:name) { nil }
        include_context 'leave attribute intact', attr: :name
      end

      context 'with a missing org option' do
        let(:org) { nil }
        include_context 'leave attribute intact', attr: :organisation
      end

      context 'with a missing admin option' do
        let(:admin) { nil }
        include_context 'leave attribute intact', attr: :registrant_name
      end

      context 'with a missing mail option' do
        let(:mail) { nil }
        include_context 'leave attribute intact', attr: :registrant_mail
      end

      context 'with a missing aud option' do
        let(:aud) { nil }
        include_context 'leave attribute intact', attr: :audience
      end

      context 'with a missing url option' do
        let(:url) { nil }
        include_context 'leave attribute intact', attr: :endpoint
      end

      context 'with a missing type option' do
        let(:type) { nil }
        include_context 'leave attribute intact', attr: :type
      end

      context 'with a missing secret option' do
        let(:secret) { nil }
        include_context 'leave attribute intact', attr: :secret
      end

      context 'with no change' do
        let(:attrs) { existing.attributes }

        it 'indicates no change has been made' do
          expect { run }.to raise_error(SystemExit)
            .and output(/No change required/).to_stderr
        end
      end
    end
  end
end

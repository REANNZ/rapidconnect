# frozen_string_literal: true
require './app/models/claims_set'
require './app/models/attributes_claim'

RSpec.describe ClaimsSet do
  let(:iss) { 'https://rapid.example.com' }
  let(:aud) { 'https://service.example.com' }
  let(:jti) { 'abcdefghijklmnopqrstuvwxyz' }
  let(:auth_subject) { attributes_for(:subject) }
  let(:attributes_claim) { AttributesClaim.new(iss, aud, auth_subject) }

  subject { ClaimsSet.send(type, iss, aud, attributes_claim) }

  around { |example| Timecop.freeze { example.run } }

  before do
    allow(SecureRandom).to receive(:urlsafe_base64).with(24).and_return(jti)
  end

  shared_examples 'a jwt claims set' do
    it 'sets the iss claim' do
      expect(subject.claims[:iss]).to eq(iss)
    end

    it 'sets the aud claim' do
      expect(subject.claims[:aud]).to eq(aud)
    end

    it 'sets the iat claim' do
      expect(subject.claims[:iat]).to eq(Time.now)
    end

    it 'sets the jti claim' do
      expect(subject.claims[:jti]).to eq(jti)
    end

    it 'sets the nbf claim' do
      expect(subject.claims[:nbf]).to eq(1.minute.ago)
    end

    it 'sets the exp claim' do
      expect(subject.claims[:exp]).to eq(2.minutes.from_now)
    end

    it 'sets the typ claim' do
      expect(subject.claims[:typ]).to eq('authnresponse')
    end

    context '#to_jws' do
      let(:secret) { 'abcd' }
      let(:jws) { subject.to_jws(secret) }

      it 'looks valid' do
        expect(jws).to match(/[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+/)
      end

      it 'decodes to the claims' do
        claims = subject.claims.merge(
          iat: subject.claims[:iat].to_i,
          exp: subject.claims[:exp].to_i,
          nbf: subject.claims[:nbf].to_i
        )
        expected = JSON.load(JSON.dump(claims))

        expect(JSON::JWT.decode(jws, secret)).to eq(expected)
      end

      it 'is verified by the secret' do
        expect { JSON::JWT.decode(jws, 'wrong secret') }
          .to raise_error(JSON::JWS::VerificationFailed)
      end
    end
  end

  shared_examples 'a research claims set' do
    it 'sets the https://aaf.edu.au/attributes claim' do
      attrs = attributes_claim.attributes.slice(*expected_attrs)
      expect(subject.claims[:'https://aaf.edu.au/attributes']).to eq(attrs)
    end

    it 'sets the sub claim' do
      expect(subject.claims[:sub])
        .to eq(attributes_claim.attributes[:edupersontargetedid])
    end
  end

  context 'for research services' do
    let(:type) { :research }
    let(:expected_attrs) do
      %i(cn mail displayname edupersontargetedid givenname surname
         edupersonscopedaffiliation edupersonprincipalname)
    end

    it_behaves_like 'a jwt claims set'
    it_behaves_like 'a research claims set'
  end

  context 'for auresearch services' do
    let(:type) { :auresearch }
    let(:expected_attrs) do
      %i(cn mail displayname edupersontargetedid givenname surname
         edupersonscopedaffiliation edupersonprincipalname
         auedupersonsharedtoken)
    end

    it_behaves_like 'a jwt claims set'
    it_behaves_like 'a research claims set'
  end

  context 'for zendesk services' do
    let(:type) { :zendesk }
    it_behaves_like 'a jwt claims set'

    it 'sets the name claim' do
      expect(subject.claims[:name]).to eq(attributes_claim.attributes[:cn])
    end

    it 'sets the email claim' do
      expect(subject.claims[:email]).to eq(attributes_claim.attributes[:mail])
    end

    it 'sets the external_id claim' do
      expect(subject.claims[:external_id])
        .to eq(attributes_claim.attributes[:edupersontargetedid])
    end

    it 'sets the o claim' do
      expect(subject.claims[:o]).to eq(attributes_claim.attributes[:o])
    end

    it 'has no attributes claim' do
      expect(subject.claims).not_to have_key(:'https://aaf.edu.au/attributes')
    end
  end

  context 'for freshdesk services' do
    let(:type) { :freshdesk }
    it_behaves_like 'a jwt claims set'

    it 'sets the name claim' do
      expect(subject.claims[:name]).to eq(attributes_claim.attributes[:cn])
    end

    it 'sets the email claim' do
      expect(subject.claims[:email]).to eq(attributes_claim.attributes[:mail])
    end

    it 'sets the external_id claim' do
      expect(subject.claims[:external_id])
        .to eq(attributes_claim.attributes[:edupersontargetedid])
    end

    it 'sets the o claim' do
      expect(subject.claims[:o]).to eq(attributes_claim.attributes[:o])
    end

    it 'has no attributes claim' do
      expect(subject.claims).not_to have_key(:'https://aaf.edu.au/attributes')
    end
  end
end

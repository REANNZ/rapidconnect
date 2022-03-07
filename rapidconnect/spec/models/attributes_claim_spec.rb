# frozen_string_literal: true

require './app/models/attributes_claim'

RSpec.describe AttributesClaim do
  let(:iss) { 'https://rapid.example.com' }
  let(:aud) { 'https://service.example.com' }
  let(:auth_subject) do
    attrs = {
      principal: 'https://idp.example.com!https://rapid.example.com!oooooooooh',
      mail: 'testuser@example.com'
    }

    attributes_for(:subject, attrs)
  end

  subject { AttributesClaim.new(iss, aud, auth_subject) }

  it 'sets the cn attribute' do
    expect(subject.attributes[:cn]).to eq(auth_subject[:cn])
  end

  it 'sets the mail attribute' do
    expect(subject.attributes[:mail]).to eq(auth_subject[:mail])
  end

  it 'sets the surname attribute' do
    expect(subject.attributes[:surname]).to eq(auth_subject[:surname])
  end

  it 'sets the displayname attribute' do
    expect(subject.attributes[:displayname]).to eq(auth_subject[:display_name])
  end

  it 'sets the givenname attribute' do
    expect(subject.attributes[:givenname]).to eq(auth_subject[:given_name])
  end

  it 'sets the o attribute' do
    expect(subject.attributes[:o]).to eq(auth_subject[:organization])
  end

  it 'sets the edupersonscopedaffiliation attribute' do
    expect(subject.attributes[:edupersonscopedaffiliation])
      .to eq(auth_subject[:scoped_affiliation])
  end

  it 'sets the edupersonprincipalname attribute' do
    expect(subject.attributes[:edupersonprincipalname])
      .to eq(auth_subject[:principal_name])
  end

  it 'sets the auedupersonsharedtoken attribute' do
    expect(subject.attributes[:auedupersonsharedtoken])
      .to eq(auth_subject[:shared_token])
  end

  it 'sets the edupersontargetedid attribute' do
    expect(subject.attributes[:edupersontargetedid])
      .to eq('https://rapid.example.com!https://service.example.com!' \
             'ZgIn68qu5WHxfS94DhlveAhgY4o=')
  end

  context 'when a legacy edupersontargetedid exists for the subject and service' do
    before do
      stub_redis = instance_double(Redis)
      allow(Redis).to receive(:new).and_return stub_redis
      expect(stub_redis).to receive(:get)
        .with("eptid:#{aud}:#{OpenSSL::Digest::SHA256.hexdigest(auth_subject[:principal])}")
        .and_return 'legacy_edupersontargetedid'
    end

    it 'has the legacy edupersontargetedid' do
      expect(subject.attributes[:edupersontargetedid])
        .to eq('legacy_edupersontargetedid')
    end
  end

  it 'has the same edupersontargetedid attribute if email address changes' do
    new_auth_subject = auth_subject.merge(mail: 'other@example.com')
    new_claim = AttributesClaim.new(iss, aud, new_auth_subject)

    expect(new_claim.attributes[:edupersontargetedid])
      .to eq(subject.attributes[:edupersontargetedid])
  end

  it 'has a different edupersontargetedid for another user' do
    new_principal = "#{auth_subject[:principal]}i"
    new_auth_subject = auth_subject.merge(principal: new_principal)
    new_claim = AttributesClaim.new(iss, aud, new_auth_subject)

    expect(new_claim.attributes[:edupersontargetedid])
      .not_to eq(subject.attributes[:edupersontargetedid])
  end
end

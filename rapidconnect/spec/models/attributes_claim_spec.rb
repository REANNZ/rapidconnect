require './app/models/attributes_claim'

RSpec.describe AttributesClaim do
  let(:iss) { 'https://rapid.example.com' }
  let(:aud) { 'https://service.example.com' }
  let(:auth_subject) do
    given_name = Faker::Name.first_name
    surname = Faker::Name.last_name

    {
      principal: 'https://idp.example.com!https://rapid.example.com!oooooooooh',
      cn: "#{given_name} #{surname}",
      display_name: "#{given_name} #{surname}",
      given_name: given_name,
      surname: surname,
      mail: 'testuser@example.com',
      principal_name: Faker::Internet.user_name("#{given_name} #{surname}"),
      scoped_affiliation: 'member@idp.example.com',
      shared_token: SecureRandom.urlsafe_base64(24)
    }
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
    # Expected value computed manually using the original `repack_principal`
    # function from the RapidConnect class.
    expect(subject.attributes[:edupersontargetedid])
      .to eq('https://rapid.example.com!https://service.example.com!' \
             'TBxeIzWIYcAVgKCnEZINqPiAYew=')
  end

  it 'has the same edupersontargetedid attribute if email address changes' do
    new_auth_subject = auth_subject.merge(mail: 'other@example.com')
    new_claim = AttributesClaim.new(iss, aud, new_auth_subject)

    expect(new_claim.attributes[:edupersontargetedid])
      .to eq(subject.attributes[:edupersontargetedid])
  end

  it 'has a different edupersontargetedid for another user' do
    new_principal = auth_subject[:principal] + 'i'
    new_auth_subject = auth_subject.merge(principal: new_principal)
    new_claim = AttributesClaim.new(iss, aud, new_auth_subject)

    expect(new_claim.attributes[:edupersontargetedid])
      .not_to eq(subject.attributes[:edupersontargetedid])
  end
end

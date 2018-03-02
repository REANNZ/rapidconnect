# frozen_string_literal: true

FactoryBot.define do
  factory :rapid_connect_service do
    name { Faker::Company.name }
    audience { Faker::Internet.url }
    endpoint { Faker::Internet.url }
    secret 'abcdefghijklmnopqrstuvwxyz'
    type 'research'
    enabled true
    organisation { Faker::Company.name }
    registrant_name { Faker::Name.name }
    registrant_mail { Faker::Internet.email(registrant_name) }
    created_at { Time.now.utc.to_i }

    to_create do |instance|
      Redis.new.hset('serviceproviders', instance.identifier!, instance.to_json)
    end
  end

  factory :subject, class: 'Hash' do
    transient do
      idp_domain { Faker::Internet.domain_name }
      idp_host { "idp.#{idp_domain}" }
      sp_host { "rapid.#{Faker::Internet.domain_name}" }
      idp_entity_id { "https://#{idp_host}/idp/shibboleth" }
      sp_entity_id { "https://#{sp_host}/shibboleth" }
    end

    organization { Faker::Company.name }
    given_name { Faker::Name.first_name }
    surname { Faker::Name.last_name }
    cn { "#{given_name} #{surname}" }
    display_name { "#{given_name} #{surname}" }
    principal_name { Faker::Internet.user_name("#{given_name} #{surname}") }
    mail { "#{principal_name}@#{idp_domain}" }
    principal { "#{idp_entity_id}!#{sp_entity_id}!#{SecureRandom.base64(21)}" }
    scoped_affiliation { "member@#{idp_domain}" }
    orcid { Faker::Base.bothify('http://orcid.org/0000-?000-####-####') }
    shared_token { SecureRandom.urlsafe_base64(24) }

    initialize_with { attributes.dup }
  end
end

FactoryGirl.define do
  factory :rapid_connect_service do
    name { Faker::Company.name }
    audience { Faker::Internet.url }
    endpoint { Faker::Internet.url }
    secret 'abcdefghijklmnopqrstuvwxyz'
    enabled true
    organisation { Faker::Company.name }
    registrant_name { Faker::Name.name }
    registrant_mail { Faker::Internet.email(registrant_name) }
  end
end

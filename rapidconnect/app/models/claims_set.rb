# require 'active_model'

# A JWT Claims Set, and logic to generate a JWS.
class ClaimsSet
  attr_reader :claims

  class <<self
    def research(iss, aud, attributes_claim)
      new(iss, aud, attributes_claim.attributes
        .except(:auedupersonsharedtoken, :o))
    end

    def auresearch(iss, aud, attributes_claim)
      new(iss, aud, attributes_claim.attributes.except(:o))
    end

    def zendesk(iss, aud, attributes_claim)
      attrs = attributes_claim.attributes

      new(iss, aud, attrs).tap do |claims_set|
        claims = claims_set.claims
        claims.transform_keys! { |k| k == :sub ? :external_id : k }
        claims.merge!(email: attrs[:mail], o: attrs[:o], name: attrs[:cn])
        claims.delete(:'https://aaf.edu.au/attributes')
      end
    end
  end

  def initialize(iss, aud, attrs)
    @claims = base_claims.merge('https://aaf.edu.au/attributes'.to_sym => attrs)
              .merge(iss: iss, aud: aud, sub: attrs[:edupersontargetedid])
  end

  def to_jws(secret)
    JSON::JWT.new(claims).sign(secret).to_s
  end

  private

  def base_claims
    {
      iat: Time.now,
      nbf: 1.minute.ago,
      exp: 2.minutes.from_now,
      jti: SecureRandom.urlsafe_base64(24),
      typ: 'authnresponse'
    }
  end
end

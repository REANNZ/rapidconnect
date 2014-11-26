require 'active_model'

# Represents a registered Rapid Connect service.
class RapidConnectService
  include ActiveModel::Model
  include ActiveModel::Serializers::JSON

  attr_accessor :identifier
  attr_reader :attributes

  validates :name, :organisation, :registrant_name, :registrant_mail,
            presence: true
  validates :created_at, numericality: { allow_nil: true }
  validates :audience, :endpoint,
            presence: true, format: URI.regexp(%w(http https))
  validates :type, inclusion: { in: %w(research auresearch zendesk),
                                allow_nil: true }
  validates :secret, presence: true, length: { minimum: 16 }

  validate :uris_can_be_parsed

  @attribute_names = %w(
    name audience endpoint secret enabled type created_at
    organisation registrant_name registrant_mail
  )

  @attribute_names.each do |n|
    define_method(n) { @attributes[n.to_s] }
    define_method(:"#{n}=") { |v| @attributes[n.to_s] = v }
  end

  def initialize
    @attributes = {}
  end

  def identifier!
    self.identifier ||= SecureRandom.urlsafe_base64
  end

  def attributes=(attrs)
    unknown = attrs.keys.map(&:to_s) - self.class.attribute_names
    fail("Bad attribute: #{unknown}") unless unknown.empty?
    attrs.each { |k, v| send(:"#{k}=", v) }

    upgrade
  end

  def to_s
    "RapidService(identifier=#{identifier || 'nil'} name=`#{name}`)"
  end

  class <<self
    attr_reader :attribute_names
  end

  private

  def upgrade
    self.type ||= 'research'
  end

  def uris_can_be_parsed
    errors.add(:audience, 'is not a valid URI') unless can_parse?(audience)
    errors.add(:endpoint, 'is not a valid URI') unless can_parse?(endpoint)
  end

  def can_parse?(uri)
    URI.parse(uri)
    true
  rescue
    false
  end
end

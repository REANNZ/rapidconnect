require 'active_model'

# Represents a registered Rapid Connect service.
class RapidConnectService
  include ActiveModel::Model
  include ActiveModel::Serializers::JSON

  attr_accessor :identifier
  attr_reader :attributes

  validates :name, :organisation, :registrant_name, :registrant_mail,
            presence: true
  validates :audience, :endpoint,
            presence: true, format: URI.regexp(%w(http https))
  validates :secret, presence: true, length: { minimum: 16 }

  @attribute_names = %w(
    name audience endpoint secret enabled
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
  end

  def to_s
    "RapidService(identifier=#{identifier || 'nil'} name=`#{name}`)"
  end

  class <<self
    attr_reader :attribute_names
  end
end

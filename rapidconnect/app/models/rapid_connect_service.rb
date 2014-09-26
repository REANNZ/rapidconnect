require 'active_model'

# Represents a registered Rapid Connect service.
class RapidConnectService
  include ActiveModel::Model
  include ActiveModel::Serializers::JSON

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

  def attributes=(attrs)
    attrs.each { |k, v| send(:"#{k}=", v) }
  end

  class <<self
    attr_reader :attribute_names
  end
end

# frozen_string_literal: true
require 'active_model'

# Represents a registered Rapid Connect service.
class RapidConnectService
  include ActiveModel::Model
  include ActiveModel::Serializers::JSON
  include ActiveModel::Dirty

  attr_accessor :identifier
  attr_reader :attributes

  URI_FIELDS = [:audience, :endpoint].freeze

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

    define_method(:"#{n}=") do |v|
      send(:"#{n}_will_change!") unless @attributes[n.to_s] == v
      @attributes[n.to_s] = v
    end
  end

  define_attribute_methods @attribute_names

  def initialize
    @attributes = {}
  end

  def from_json(*args)
    super.tap { clear_changes_information }
  end

  def identifier!
    self.identifier ||= SecureRandom.urlsafe_base64
  end

  def attributes=(attrs)
    unknown = attrs.keys.map(&:to_s) - self.class.attribute_names
    raise("Bad attribute: #{unknown}") unless unknown.empty?
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
    URI_FIELDS.each do |field|
      unless can_parse?(@attributes[field.to_s])
        errors.add(field, 'is not a valid URI')
      end
    end
  end

  def can_parse?(uri)
    URI.parse(uri)
    true
  rescue
    false
  end
end

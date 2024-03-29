# frozen_string_literal: true

require 'active_model'

# Represents a registered Rapid Connect service.
class RapidConnectService
  include ActiveModel::Model
  include ActiveModel::Serializers::JSON
  include ActiveModel::Dirty

  attr_accessor :identifier

  URI_FIELDS = %i[audience endpoint].freeze

  validates :name, :organisation, :registrant_name, :registrant_mail,
            presence: true
  validates :created_at, numericality: { allow_nil: true }
  validates :audience, :endpoint,
            presence: true, format: URI::DEFAULT_PARSER.make_regexp(%w[http https])
  validates :type, inclusion: { in: %w[research auresearch zendesk freshdesk],
                                allow_nil: true }
  validates :secret, presence: true, length: { minimum: 16 }

  validate :uris_can_be_parsed

  @attribute_names = %w[
    name audience endpoint secret enabled type created_at
    organisation registrant_name registrant_mail
  ]

  @attribute_names.each do |n|
    define_method(n) { @service_attributes[n.to_s] }

    define_method(:"#{n}=") do |v|
      send(:"#{n}_will_change!") unless @service_attributes[n.to_s] == v
      @service_attributes[n.to_s] = v
    end
  end

  define_attribute_methods @attribute_names

  def initialize
    @service_attributes = {}
  end

  def from_json(*args)
    super.tap { clear_changes_information }
  end

  def identifier!
    self.identifier ||= SecureRandom.urlsafe_base64
  end

  def attributes
    @service_attributes
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

  class << self
    attr_reader :attribute_names
  end

  private

  def upgrade
    self.type ||= 'research'
  end

  def uris_can_be_parsed
    URI_FIELDS.each do |field|
      errors.add(field, 'is not a valid URI') unless can_parse?(@service_attributes[field.to_s])
    end
  end

  def can_parse?(uri)
    URI.parse(uri)
    true
  rescue
    false
  end
end

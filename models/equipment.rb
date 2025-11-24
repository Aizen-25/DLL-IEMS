require 'active_record'

class Equipment < ActiveRecord::Base
  self.table_name = 'equipments'
  validates :name, presence: true
  # Serial numbers are optional (can be provided later during deployment).
  # Keep uniqueness when present, but allow nil/blank values.
  validates :serial_number, uniqueness: { allow_nil: true, allow_blank: true }
  validates :quantity, numericality: { only_integer: true, greater_than_or_equal_to: 0 }
  validates :purchase_price, numericality: { greater_than_or_equal_to: 0 }

  after_create :log_create_activity
  after_update :log_update_activity
  after_destroy :log_destroy_activity

  private
  def log_create_activity
    Activity.create(trackable: self, action: 'create', changes_made: attributes.to_json, user_name: 'system')
  end

  def log_update_activity
    Activity.create(trackable: self, action: 'update', changes_made: saved_changes.to_json, user_name: 'system')
  end

  def log_destroy_activity
    Activity.create(trackable_type: self.class.name, trackable_id: id, action: 'destroy', changes_made: attributes.to_json, user_name: 'system')
  end
end

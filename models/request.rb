require 'active_record'

class Request < ActiveRecord::Base
  self.table_name = 'requests'

  belongs_to :equipment, optional: true

  validates :requester_name, presence: true
  validates :quantity, numericality: { only_integer: true, greater_than: 0 }

  scope :pending, -> { where(status: 'pending') }
  scope :approved, -> { where(status: 'approved') }

  after_create :log_create_activity
  after_update :log_update_activity

  private
  def log_create_activity
    Activity.create(trackable: self, action: 'create_request', changes_made: attributes.to_json, user_name: requester_name || 'system')
  end

  def log_update_activity
    Activity.create(trackable: self, action: "update_request_#{status}", changes_made: saved_changes.to_json, user_name: requester_name || 'system')
  end
end

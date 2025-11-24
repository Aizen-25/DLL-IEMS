require 'active_record'

class UserEquipment < ActiveRecord::Base
  belongs_to :user, optional: false
  belongs_to :equipment, optional: false
  belongs_to :request, optional: true

  scope :active, -> { where(active: true) }

  def mark_returned!
    update(returned_at: Time.now, active: false)
  end
end

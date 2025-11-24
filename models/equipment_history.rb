require 'active_record'

class EquipmentHistory < ActiveRecord::Base
  self.table_name = 'equipment_histories'

  belongs_to :equipment
  belongs_to :user, optional: true
  belongs_to :user_equipment, optional: true
  belongs_to :request, optional: true

  validates :action, presence: true

  def details_hash
    begin
      JSON.parse(details || '{}')
    rescue
      {}
    end
  end
end

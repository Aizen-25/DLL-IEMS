require 'active_record'

class Activity < ActiveRecord::Base
  self.table_name = 'activities'

  belongs_to :trackable, polymorphic: true, optional: true

  def changes_hash
    begin
      JSON.parse(changes_made)
    rescue
      {}
    end
  end
end

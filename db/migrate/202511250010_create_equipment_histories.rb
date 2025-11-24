class CreateEquipmentHistories < ActiveRecord::Migration[6.0]
  def change
    create_table :equipment_histories do |t|
      t.integer :equipment_id, null: false
      t.integer :user_id
      t.integer :user_equipment_id
      t.integer :request_id
      t.string  :action, null: false
      t.text    :details
      t.datetime :occurred_at, null: false, default: -> { 'CURRENT_TIMESTAMP' }
      t.timestamps
    end

    add_index :equipment_histories, :equipment_id
    add_index :equipment_histories, :user_id
    add_index :equipment_histories, :user_equipment_id
    add_index :equipment_histories, :request_id
    add_index :equipment_histories, :action
  end
end

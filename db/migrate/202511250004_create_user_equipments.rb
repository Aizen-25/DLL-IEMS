class CreateUserEquipments < ActiveRecord::Migration[7.0]
  def change
    create_table :user_equipments do |t|
      t.integer :user_id, null: false
      t.integer :equipment_id, null: false
      t.integer :request_id, null: true
      t.string  :serial
      t.date    :purchase_date
      t.datetime :assigned_at
      t.datetime :returned_at
      t.integer :unit_index
      t.boolean :active, default: true
      t.timestamps
    end
    add_index :user_equipments, :user_id
    add_index :user_equipments, :equipment_id
    add_index :user_equipments, :request_id
  end
end

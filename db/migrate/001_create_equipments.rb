class CreateEquipments < ActiveRecord::Migration[7.0]
  def change
    create_table :equipments do |t|
      t.string :name, null: false
      t.string :serial_number, null: false
      t.string :model
      t.string :vendor
      t.date :purchase_date
      t.date :warranty_until
      t.string :status, default: 'available'
      t.string :location
      t.string :category
      t.text :notes
      t.timestamps
    end
    add_index :equipments, :serial_number, unique: true
  end
end

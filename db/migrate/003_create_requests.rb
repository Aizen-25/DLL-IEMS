class CreateRequests < ActiveRecord::Migration[7.0]
  def change
    create_table :requests do |t|
      t.integer :equipment_id
      t.integer :quantity, default: 1, null: false
      t.string :requester_name
      t.integer :requester_id
      t.string :status, default: 'pending'
      t.datetime :requested_at
      t.datetime :approved_at
      t.date :checkout_date
      t.date :expected_return_date
      t.date :returned_at
      t.text :notes

      t.timestamps
    end
    add_index :requests, :status
    add_index :requests, :equipment_id
  end
end

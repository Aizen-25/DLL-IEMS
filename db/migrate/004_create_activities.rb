class CreateActivities < ActiveRecord::Migration[7.0]
  def change
    create_table :activities do |t|
      t.string :trackable_type
      t.integer :trackable_id
      t.string :action
      t.integer :user_id
      t.string :user_name
      t.text :changes_made
      t.datetime :created_at
    end
    add_index :activities, [:trackable_type, :trackable_id]
    add_index :activities, :user_id
  end
end

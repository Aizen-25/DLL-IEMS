class AddQuantityAndPriceToEquipments < ActiveRecord::Migration[7.0]
  def change
    add_column :equipments, :quantity, :integer, default: 1, null: false
    add_column :equipments, :purchase_price, :decimal, precision: 10, scale: 2, default: 0.0, null: false
  end
end

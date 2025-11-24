# This file is auto-generated from the current state of the database. Instead
# of editing this file, please use the migrations feature of Active Record to
# incrementally modify your database, and then regenerate this schema definition.
#
# This file is the source Rails uses to define your schema when running `bin/rails
# db:schema:load`. When creating a new database, `bin/rails db:schema:load` tends to
# be faster and is potentially less error prone than running all of your
# migrations from scratch. Old migrations may fail to apply correctly if those
# migrations use external dependencies or application code.
#
# It's strongly recommended that you check this file into your version control system.

ActiveRecord::Schema[7.2].define(version: 202511250010) do
  create_table "activities", force: :cascade do |t|
    t.string "trackable_type"
    t.integer "trackable_id"
    t.string "action"
    t.integer "user_id"
    t.string "user_name"
    t.text "changes_made"
    t.datetime "created_at"
    t.index ["trackable_type", "trackable_id"], name: "index_activities_on_trackable_type_and_trackable_id"
    t.index ["user_id"], name: "index_activities_on_user_id"
  end

  create_table "equipment_histories", force: :cascade do |t|
    t.integer "equipment_id", null: false
    t.integer "user_id"
    t.integer "user_equipment_id"
    t.integer "request_id"
    t.string "action", null: false
    t.text "details"
    t.datetime "occurred_at", precision: nil, default: -> { "CURRENT_TIMESTAMP" }, null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["action"], name: "index_equipment_histories_on_action"
    t.index ["equipment_id"], name: "index_equipment_histories_on_equipment_id"
    t.index ["request_id"], name: "index_equipment_histories_on_request_id"
    t.index ["user_equipment_id"], name: "index_equipment_histories_on_user_equipment_id"
    t.index ["user_id"], name: "index_equipment_histories_on_user_id"
  end

  create_table "equipments", force: :cascade do |t|
    t.text "name"
    t.text "serial_number"
    t.text "model"
    t.text "vendor"
    t.date "purchase_date"
    t.date "warranty_until"
    t.text "status"
    t.text "location"
    t.text "category"
    t.text "notes"
    t.integer "quantity"
    t.decimal "purchase_price"
    t.datetime "created_at", precision: nil
    t.datetime "updated_at", precision: nil
    t.string "brand"
    t.index ["serial_number"], name: "index_equipments_on_serial_number", unique: true
  end

  create_table "requests", force: :cascade do |t|
    t.integer "equipment_id"
    t.integer "quantity", default: 1, null: false
    t.string "requester_name"
    t.integer "requester_id"
    t.string "status", default: "pending"
    t.datetime "requested_at"
    t.datetime "approved_at"
    t.date "checkout_date"
    t.date "expected_return_date"
    t.date "returned_at"
    t.text "notes"
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["equipment_id"], name: "index_requests_on_equipment_id"
    t.index ["status"], name: "index_requests_on_status"
  end

  create_table "user_equipments", force: :cascade do |t|
    t.integer "user_id", null: false
    t.integer "equipment_id", null: false
    t.integer "request_id"
    t.string "serial"
    t.date "purchase_date"
    t.datetime "assigned_at"
    t.datetime "returned_at"
    t.integer "unit_index"
    t.boolean "active", default: true
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.index ["equipment_id"], name: "index_user_equipments_on_equipment_id"
    t.index ["request_id"], name: "index_user_equipments_on_request_id"
    t.index ["user_id"], name: "index_user_equipments_on_user_id"
  end

  create_table "users", force: :cascade do |t|
    t.string "username", null: false
    t.string "password_digest", null: false
    t.string "role", default: "normal", null: false
    t.datetime "created_at", null: false
    t.datetime "updated_at", null: false
    t.boolean "must_change_password", default: false, null: false
    t.datetime "password_changed_at"
    t.string "temporary_password"
  end
end

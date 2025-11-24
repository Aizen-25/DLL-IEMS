require 'bcrypt'

class User < ActiveRecord::Base
  include BCrypt

  validates :username, presence: true, uniqueness: true
  validates :password_digest, presence: true
  validates :role, inclusion: { in: %w[normal semi-admin super-admin] }

  def password
    @password ||= Password.new(password_digest)
  end

  def password=(new_password)
    @password = Password.create(new_password)
    self.password_digest = @password
  end

  def super_admin?
    role == 'super-admin'
  end

  def semi_admin?
    role == 'semi-admin'
  end

  def normal_user?
    role == 'normal'
  end
end
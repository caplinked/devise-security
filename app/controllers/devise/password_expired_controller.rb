class Devise::PasswordExpiredController < DeviseController
  skip_before_action :handle_password_change
  before_action :skip_password_change, only: [:show, :update]
  prepend_before_action :authenticate_scope!, :only => [:show, :update]

  def show
    respond_with(resource)
  end

  def update
    resource.extend(Devise::Models::DatabaseAuthenticatablePatch)
    if resource.update_with_password(resource_params)
      warden.session(scope)['password_expired'] = false
      set_flash_message :notice, :updated
      bypass_sign_in resource, scope: scope
      redirect_to stored_location_for(scope) || :root
    else
      clean_up_passwords(resource)
      respond_with(resource, action: :show)
    end
  end

  private

  def skip_password_change
    return if !resource.nil?
    redirect_to :root
  end

  def resource_params
    permitted_params = [:current_password, :password, :password_confirmation]

    if params.respond_to?(:permit)
      params.require(resource_name).permit(*permitted_params)
    else
      params[scope].slice(*permitted_params)
    end
  end

  def scope
    resource_name.to_sym
  end

  def authenticate_scope!
    send(:"authenticate_#{resource_name}!")
    self.resource = send("current_#{resource_name}")
  end

  def bypass_sign_in(resource, scope: nil)
    scope ||= Devise::Mapping.find_scope!(resource)
    expire_data_after_sign_in!
    warden.session_serializer.store(resource, scope)
  end

  def expire_data_after_sign_in!
    # session.keys will return an empty array if the session is not yet loaded.
    # This is a bug in both Rack and Rails.
    # A call to #empty? forces the session to be loaded.
    session.empty?
    session.keys.grep(/^devise\./).each { |k| session.delete(k) }
  end
end

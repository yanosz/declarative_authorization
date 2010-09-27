# Authorization::AuthorizationInModel
require File.dirname(__FILE__) + '/authorization.rb'
require File.dirname(__FILE__) + '/obligation_scope.rb'

module Authorization
  
  module AuthorizationInModel
    ReadAllPrivilege = :read
    WriteAllPrivilege = :write
    
    # If the user meets the given privilege, permitted_to? returns true
    # and yields to the optional block.
    def permitted_to? (privilege, options = {}, &block)
      options = {
        :user =>  Authorization.current_user,
        :object => self
      }.merge(options)
      Authorization::Engine.instance.permit?(privilege,
          {:user => options[:user],
           :object => options[:object]},
          &block)
    end

    # Works similar to the permitted_to? method, but doesn't accept a block
    # and throws the authorization exceptions, just like Engine#permit!
    def permitted_to! (privilege, options = {} )
      options = {
        :user =>  Authorization.current_user,
        :object => self
      }.merge(options)

logger.debug "Checking for: #{self.class.name}"

      Authorization::Engine.instance.permit!(privilege,
          {:user => options[:user],
           :object => options[:object]})
    end
    
    #
    #  Returns true or false, depending on whether we can read/write a column based on all our rules 
    #
    #  PARAMS
    #
    #  mode Symbol. :read/:write
    #  attribute String. the column we want to check
    #  application_defaults Boolean, whether we want to incude the application defaults or not
    #
    #  RETURNS
    #
    # boolean, true/false
    #
    def allowed?(mode, attribute, exclude_application_defaults = false)
      # Return false if mode is not read or write
      return false unless [:read, :write].include?(mode)
      
      # Variables needed to make checks
      access_all_columns_sym = (mode == :read) ? ReadAllPrivilege : WriteAllPrivilege
      whitelist_sym = (mode == :read) ? attribute.to_sym : (attribute + '=').to_sym
      acl_sym = (mode == :read) ? ('read_' + attribute).to_sym : ('write_' + attribute).to_sym
      
      # Perform checks, returns early on success
      return true if attribute.to_s == self.class.primary_key.to_s # Always return true on primary key
      return true if !exclude_application_defaults && get_application_default_attributes.include?(attribute.to_sym) # Test application defaults first
      return true if permitted_to_without_include_attributes?(access_all_columns_sym) # Are we allowed read/write all?
      return true if get_white_list.include?(whitelist_sym) # White Listed
      return true if permitted_to_without_include_attributes?(acl_sym) # read/write_{attribute} given explicitly
      false # Not allowed, return false
    end
    
    def self.included(base) # :nodoc:
      #base.extend(ClassMethods)
      base.module_eval do
        scopes[:with_permissions_to] = lambda do |parent_scope, *args|
          options = args.last.is_a?(Hash) ? args.pop : {}
          privilege = (args[0] || :read)
          #Patch - support privilege arrays
          privileges = (privilege.is_a?(Array) ? privilege : [privilege]).map {|p| p.to_sym}
          #End Patch
          context =
              if options[:context]
                options[:context]
              elsif parent_scope.respond_to?(:proxy_reflection)
                parent_scope.proxy_reflection.klass.name.tableize.to_sym
              elsif parent_scope.respond_to?(:decl_auth_context)
                parent_scope.decl_auth_context
              else
                parent_scope.name.tableize.to_sym
              end
          
          user = options[:user] || Authorization.current_user

          engine = options[:engine] || Authorization::Engine.instance
          engine.permit!(privileges, :user => user, :skip_attribute_test => true,
                         :context => context)

          obligation_scope_for( privileges, :user => user,
              :context => context, :engine => engine, :model => parent_scope)
        end
        
        # Builds and returns a scope with joins and conditions satisfying all obligations.
        def self.obligation_scope_for( privileges, options = {} )
          options = {
            :user => Authorization.current_user,
            :context => nil,
            :model => self,
            :engine => nil,
          }.merge(options)
          engine = options[:engine] || Authorization::Engine.instance

          obligation_scope = ObligationScope.new( options[:model], {} )
          engine.obligations( privileges, :user => options[:user], :context => options[:context] ).each do |obligation|
            obligation_scope.parse!( obligation )
          end

          obligation_scope.scope
        end

        # Named scope for limiting query results according to the authorization
        # of the current user.  If no privilege is given, :+read+ is assumed.
        # 
        #   User.with_permissions_to
        #   User.with_permissions_to(:update)
        #   User.with_permissions_to(:update, :context => :users)
        #   
        # As in the case of other named scopes, this one may be chained:
        #   User.with_permission_to.find(:all, :conditions...)
        # 
        # Options
        # [:+context+]
        #   Context for the privilege to be evaluated in; defaults to the
        #   model's table name.
        # [:+user+]
        #   User to be used for gathering obligations; defaults to the
        #   current user.
        #
        def self.with_permissions_to (*args)
          scopes[:with_permissions_to].call(self, *args)
        end
        
        # Activates model security for the current model.  Then, CRUD operations
        # are checked against the authorization of the current user.  The
        # privileges are :+create+, :+read+, :+update+ and :+delete+ in the
        # context of the model.  By default, :+read+ is not checked because of
        # performance impacts, especially with large result sets.
        # 
        #   class User < ActiveRecord::Base
        #     using_access_control
        #   end
        #   
        # If an operation is not permitted, a Authorization::AuthorizationError
        # is raised.
        #
        # To activate model security on all models, call using_access_control
        # on ActiveRecord::Base
        #   ActiveRecord::Base.using_access_control
        # 
        # Available options
        # [:+context+] Specify context different from the models table name.
        # [:+include_read+] Also check for :+read+ privilege after find.
        #
        def self.using_access_control (options = {})
          options = {
            :context => nil,
            :include_read => false
          }.merge(options)

          class_eval do            
            if options[:include_read]
              # If we are limiting access by options[:include_attributes], then we do not want to do the check on the entire object
              # instead we will allow the individual checks to determine what passes and what failes
              unless(options[:include_attributes])
                # after_find is only called if after_find is implemented
                after_find do |object|
                  Authorization::Engine.instance.permit!(:read, :object => object,
                    :context => options[:context])
                end
            
                if Rails.version < "3"
                  def after_find; end
                end
              end
            end
            
            # If we are limiting access by options[:include_attributes], then we do not want to do the check on the entire object
            # instead we will allow the individual checks to determine what passes and what failes
            unless(options[:include_attributes])            
              [:create, :update, [:destroy, :delete]].each do |action, privilege|
                send(:"before_#{action}") do |object|                
                  Authorization::Engine.instance.permit!(privilege || action, :object => object, :context => options[:context])
                end
              end
            end      
            
            #Inject an acl_write check for a given methid into method-chain
            def self.inject_acl_write_check(method_name)
              inject_acl_check(method_name,:write)
            end
            
            #Inject an acl_read check for a given methid into method-chain
            def self.inject_acl_read_check(method_name)
              inject_acl_check(method_name,:read)
            end
            
            #routine for helper methods
            def self.inject_acl_check(method_name,mode)
             command = <<-EOV
               unless respond_to?(:no_acl_#{method_name})
                 alias_method :no_acl_#{method_name}, :#{method_name} 
                 private :no_acl_#{method_name}
               end  
                def #{method_name}(*args,&block)
                  permitted_to!(:#{mode}_#{method_name}) if !permitted_to?(:#{mode})
                    return send(:no_acl_#{method_name},*args,&block)
                end
              EOV
              class_eval command
            end
            
            #Protecting an instance (used for generated  code, ie ActiveRecord)
            def inject_acl_object_check(method_name,mode)
              class_eval <<-EOV
                unless respond_to?(:no_acl_#{method_name})
                  alias_method :no_acl_#{method_name}, :#{method_name} unless respond_to?(:no_acl_#{method_name})
                  private :no_acl_#{method_name}
                end
              EOV
              command = <<-EOV
                def #{method_name}(*args,&block)
                  permitted_to!(:#{mode}_#{method_name}) if (!permitted_to?(:#{mode}))
                    return send(:no_acl_#{method_name},*args,&block)
                end
              EOV
              instance_eval command
            end
            
            #Inject acl-aware setter / getter methods into method-chain
            def inject_acl_object_getter_setter(method_name)
              inject_acl_object_check(method_name, :read)
              inject_acl_object_check("#{method_name}=",:write)
            end
            if(options[:include_attributes]) #If attribute / getter-setter-access ought to be checekd#     
              #parse attribute hash - sane input?
              raise "Illegal syntax - :include_attributes must point to an array" unless options[:include_attributes][0].is_a?(Hash)
              
              protect_ar = options[:include_attributes][0][:protect_ar] || []
              raise "Illegal syntax :protect_ar must point to an array" unless protect_ar.blank? || protect_ar.is_a?(Array)
              protect_ar = protect_ar.to_set
              
              protect_read = options[:include_attributes][0][:protect_read]
              raise "Illegal syntax :protect_read must point to an array" unless protect_read.nil? || protect_read.is_a?(Array)
              
              protect_write = options[:include_attributes][0][:protect_write]
              raise "Illegal syntax :protect_write must point to an array" unless protect_write.nil? || protect_write.is_a?(Array)

              protect_attributes = options[:include_attributes][0][:protect_attributes]
              raise "Illegal syntax :protect_attributes point to an array" unless protect_attributes.nil? || protect_attributes.is_a?(Array)

              whitelist = options[:include_attributes][0][:whitelist] || []
              raise "Illegal syntax :whitelist must point to an array" unless whitelist.blank? || whitelist.is_a?(Array)
              whitelist = whitelist.to_set
              
              application_default_attributes = options[:include_attributes][0][:application_default_attributes] || []
              raise "Illegal syntax :application_default_attributes must point to an array" unless application_default_attributes.blank? || application_default_attributes.is_a?(Array)
              application_default_attributes = application_default_attributes.to_set
              
              #Enable callback for instance-level meta programming
              def after_initialize; end
              
              # Create helper methods, that can be called from within our code to access
              # variables that are set up during initilization

              
              class_eval <<-EOV
                #
                # Method to return the white list
                #
                def get_white_list
                  [#{whitelist.to_a.collect{|c| ":#{c}"}.join(',')}]
                end
                
                #
                # Method to return the application_default_attributes
                #
                def get_application_default_attributes
                  [#{application_default_attributes.to_a.collect{|c| ":#{c}"}.join(',')}]
                end
              EOV
              
              #1a Generate guards for ar-attributes
              if protect_ar.include?(:attributes)                
                column_names.each do |name|
                  class_eval "begin; alias_method :no_acl_#{name}, :#{name};rescue;end #Alias-Methods - put acl stuff into method-chain
                  begin; alias_method :no_acl_#{name}=, :#{name}=; rescue; end
                  def #{name}() #Define getters / setter with ACL-Checks
                    permitted_to!(:read_#{name}) if !permitted_to?(:#{ReadAllPrivilege}); 
                    if(respond_to? 'no_acl_#{name}')
                      return no_acl_#{name}
                    else
                      return read_attribute(:#{name})
                    end
                  end" unless name.to_s == self.primary_key.to_s || whitelist.include?(name.to_sym) 
                  class_eval %{def #{name}=(n)
                    permitted_to!(:write_#{name}) if !permitted_to?(:#{WriteAllPrivilege});
                    if(respond_to? 'no_acl_#{name}=')
                      return no_acl_#{name}=(n)
                    else
                      return write_attribute(:#{name},n)
                    end
                  end} unless whitelist.include?(name.to_sym) 
                end
              end
              
              #1b Generate guards for non-ar attributes
              if protect_attributes
                after_initialize do |object|
                  protect_attributes.each { |attr| object.inject_acl_object_getter_setter(attr) }
                end
              end
      
              
              #2nd Generate guards for ar-proxies
              if protect_ar.include?(:proxies)
                after_initialize do |object|
                  reflect_on_all_associations.each do |assoc|
                     #Respect excludes
                      #Ok, we've to intercept these calls (See: ActiveRecord::Associations::ClassMethods)
                      # one-to-one: other_id, other_id=(id), other, other=(other), build_other(attributes={}), create_other(attributes={})
                      # one-to-many / many-to-many: others, others=(other,other,...), other_ids, other_ids=(id,id,...), others<< 
                      object.inject_acl_object_getter_setter(assoc.name.to_s) unless whitelist.include?(assoc.name)
                    
                      if(assoc.collection?) #Collection? if so, many-to-many case
                        object.inject_acl_object_getter_setter("#{assoc.name.to_s.singularize}_ids") unless whitelist.include?(assoc.name.to_sym)
                        #inject_acl_write_check("#{assoc.name}<<")
                      else
                        #object.inject_acl_object_getter_setter("#{assoc.name}_id") unless assoc.macro != :has_one || whitelist.include?(assoc.name.to_sym) #Not needed. has_one injects no id, belongs_to already has an id attribte
                        object.inject_acl_object_check("build_#{assoc.name}",:write) unless whitelist.include?(assoc.name.to_sym)
                        object.inject_acl_object_check("create_#{assoc.name}",:read) unless whitelist.include?(assoc.name.to_sym)
                      end
                  end
                end
              end
              
              #3rd - generate guards for specified methods
              #3a - read-permission required
              if(protect_read)
                after_initialize do |object|
                  protect_read.each { |method| object.inject_acl_object_check(method,:read) }
                end
              end
              
              #3b - write permission required
              if(protect_write)
                after_initialize do |object|
                  protect_write.each { |method| object.inject_acl_object_check(method,:write) }
                end
              end              
              
              #
              # Returns a hash of key, value paris that are readable
              #
              def readable_attributes 
                return attributes if permitted_to?(ReadAllPrivilege)
                attributes.reject do |k,v|
                  !allowed?(:read, k)
                end
              end
              
              #
              # Returns a hash of key, value paris that are showable, excluding application_default_attributes
              #
              def showable_attributes
                return attributes if permitted_to?(WriteAllPrivilege)
                attributes.reject do |k,v|
                  !allowed?(:read, k, true)
                end
              end
              
              #
              # Returns a hash of key, value paris that are writable
              #
              def writable_attributes
                return attributes if permitted_to?(WriteAllPrivilege)
                attributes.reject do |k,v|
                  !allowed?(:write, k)
                end
              end
              
              #
              # Returns a list of columns that are readable
              #
              def readable_columns
                readable_attributes.keys
              end
              
              #
              # Returns a list of columns that are writable
              #
              def writable_columns
                writable_attributes.keys
              end
              
              #
              # Returns a list of columns that are showable to the user
              #
              def showable_columns
                showable_attributes.keys
              end
              
              #
              # When calling permitted_to? on the model, we return true if whitelist or read/write all
              # excluding application_default_attributes
              #
              def permitted_to_with_include_attributes?(privilege, options = {}, &block)
                # Figure out what priv/attribute was passed, if it begins with read_ or write_
                if reg = privilege.to_s.match(/(^write_|^read_)(.+)/)
                  mode, attribute = reg[1].chop.to_sym, reg[2] # Split the regular expression accordingly                  
                  if allowed?(mode, attribute, true) # Exclude application_default_attributes
                    yield if block_given?
                    return true
                  end
                end
                
                # Default back to old call
                permitted_to_without_include_attributes?(privilege, options, &block)  
              end
              
              alias_method_chain :permitted_to?, :include_attributes
            end

            def self.using_access_control?
              true
            end
          end
        end

        # Returns true if the model is using model security.
        def self.using_access_control?
          false
        end
      end
    end
  end
end

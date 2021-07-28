# silvaengine_auth

## Configurations

1. The following settings should be appended to the configuration data table.

```ini
# 1. Settings of authorizer
region_name=us-east-1
user_pool_id=abc123456789
app_client_id=abc123456789,abc123456789,...
# The `custom_context_hooks` is optional
custom_context_hooks=module_name:class_name:function_name,module_name:class_name:function_name,...

# 2. Settings of silvaengine_auth
app_client_id=abc123456789
app_client_secret=abc123456789
# The `custom_signin_hooks` is optional
custom_signin_hooks=module_name:class_name:function_name,module_name:class_name:function_name,...
```

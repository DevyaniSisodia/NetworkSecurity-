import sys
print(sys.path)

try:
    from routes.insights_fix import router
    print("Successfully imported router")
    print(router)
except Exception as e:
    print(f"Error: {e}")
    
    # Try to see what's in the module
    import routes.insights
    print(dir(routes.insights))
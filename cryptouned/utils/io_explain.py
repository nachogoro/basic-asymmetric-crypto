import contextvars

# Create a context variable for explain mode
explain_mode = contextvars.ContextVar('explain_mode', default=False)

def explaining_method(func):
    """
    Wrapper to enable/disable explanations in a function based on the explain
    parameter passed to the function
    """
    def wrapper(*args, **kwargs):
        # Extract the explain flag if present, otherwise default to False
        parent_explain_mode = explain_mode.get()
        explain_enabled = kwargs.pop('explain', parent_explain_mode)

        # Set the new explain mode for this context
        token = explain_mode.set(explain_enabled)

        try:
            # Execute the function with remaining arguments
            return func(*args, **kwargs)
        finally:
            # Reset the explain mode to its previous state
            explain_mode.reset(token)

    return wrapper


def explain(*args, **kwargs):
    """
    Prints an explanation if appropriate.
    It's a no-op if explain_mode is set to False
    """
    if explain_mode.get():
        print(*args, **kwargs)


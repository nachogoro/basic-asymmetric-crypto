import contextvars

# Create a context variable for explain mode
explain_mode = contextvars.ContextVar('explain_mode', default=False)


def explaining_method(func):
    """
    Decorator that controls the explanation mode of a function.

    Any function wrapped by this decorator is able to receive an extra
    'explain' keyword argument. That parameter enables or disables the
    function's explanation output. The decorator ensures that the explanation
    mode is consistent within the current execution context (inherited between
    calls) and resets it to its previous state after the function call.

    Parameters:
    func (Callable): The function to be wrapped by the decorator.

    Returns:
    Callable: The wrapped function with explanation mode control.
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
    Print an explanation if the current context is in explanation mode.

    This function checks the current value of the 'explain_mode' context variable.
    If explanation mode is enabled, it prints the given arguments; otherwise,
    it does nothing.

    Parameters:
    *args: Variable length argument list to be printed if explanation mode is enabled.
    **kwargs: Arbitrary keyword arguments to be passed to the print function.
    """

    if explain_mode.get():
        print(*args, **kwargs)

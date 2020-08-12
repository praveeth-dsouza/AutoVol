from vol_command import execute_volatility_command


def get_new_pslist(memory_instance):

    return execute_volatility_command(memory_instance, 'pslist')



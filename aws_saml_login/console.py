import click
import datetime


def action(msg, **kwargs):
    click.secho(msg.format(**kwargs), nl=False, bold=True)


def ok(msg=' OK', **kwargs):
    click.secho(msg, fg='green', bold=True, **kwargs)


def error(msg, **kwargs):
    click.secho(' {}'.format(msg), fg='red', bold=True, **kwargs)


def warning(msg, **kwargs):
    click.secho(' {}'.format(msg), fg='yellow', bold=True, **kwargs)


class Action:

    def __init__(self, msg, **kwargs):
        self.msg = msg
        self.msg_args = kwargs
        self.errors = []

    def __enter__(self):
        action(self.msg, **self.msg_args)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            if not self.errors:
                ok()
        else:
            error('EXCEPTION OCCURRED: {}'.format(exc_val))

    def error(self, msg, **kwargs):
        error(msg, **kwargs)
        self.errors.append(msg)

    def progress(self):
        click.secho(' .', nl=False)


def format_time(ts):
    if ts == 0:
        return ''
    now = datetime.datetime.now()
    try:
        dt = datetime.datetime.fromtimestamp(ts)
    except:
        return ts
    diff = now - dt
    s = diff.total_seconds()
    if s > 3600:
        t = '{:.0f}h'.format(s / 3600)
    elif s > 60:
        t = '{:.0f}m'.format(s / 60)
    else:
        t = '{:.0f}s'.format(s)
    return '{} ago'.format(t)


def format(col, val):
    if val is None:
        val = ''
    elif col.endswith('_time'):
        val = format_time(val)
    elif isinstance(val, bool):
        val = 'yes' if val else 'no'
    else:
        val = str(val)
    return val


def choice(prompt: str, options: list):
    """
    Ask to user to select one option and return it
    """
    click.secho(prompt)
    for i, option in enumerate(options):
        if isinstance(option, tuple):
            value, label = option
        else:
            value = label = option
        click.secho('{}) {}'.format(i+1, label))
    while True:
        selection = click.prompt('Please select (1-{})'.format(len(options)), type=int)
        try:
            result = options[int(selection)-1]
            if isinstance(result, tuple):
                value, label = result
            else:
                value = result
            return value
        except:
            pass

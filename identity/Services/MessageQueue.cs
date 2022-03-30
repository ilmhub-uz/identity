using System.Collections.Concurrent;

namespace identity.Services;

public class MessageQueue<T>
{
    public SemaphoreSlim mSignal = new (0);

    private readonly ConcurrentQueue<T> _messages = new();

    public void Queue(T message)
    {
        if (message == null)
        {
            throw new ArgumentNullException(nameof(message));
        }

        _messages.Enqueue(message);

        mSignal.Release();
    }

    public async Task<T> DequeueAsync(CancellationToken cancellationToken)
    {
        await mSignal.WaitAsync(cancellationToken);
        _messages.TryDequeue(out var message);

        return message;
    }
}
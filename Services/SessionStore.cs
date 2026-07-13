using System.Collections.Concurrent;
using WirePeek.Models;

namespace WirePeek.Services;

/// <summary>
/// Thread-safe, capped in-memory store of captured sessions (ring buffer semantics).
/// Keeps the most recent <see cref="Capacity"/> sessions to avoid unbounded memory.
/// </summary>
public sealed class SessionStore
{
    public int Capacity { get; }

    private readonly ConcurrentDictionary<string, CapturedSession> _byId = new();
    private readonly LinkedList<string> _order = new(); // oldest -> newest
    private readonly object _gate = new();
    private int _counter;

    public SessionStore(int capacity = 5000) => Capacity = capacity;

    public void Add(CapturedSession session)
    {
        lock (_gate)
        {
            session.Index = ++_counter;
            _byId[session.Id] = session;
            _order.AddLast(session.Id);

            while (_order.Count > Capacity)
            {
                var oldest = _order.First!.Value;
                _order.RemoveFirst();
                _byId.TryRemove(oldest, out _);
            }
        }
    }

    public CapturedSession? Get(string id) => _byId.TryGetValue(id, out var s) ? s : null;

    public IReadOnlyList<SessionSummary> ListSummaries()
    {
        lock (_gate)
        {
            var list = new List<SessionSummary>(_order.Count);
            foreach (var id in _order)
            {
                if (_byId.TryGetValue(id, out var s))
                    list.Add(SessionSummary.From(s));
            }
            return list;
        }
    }

    public void Clear()
    {
        lock (_gate)
        {
            _byId.Clear();
            _order.Clear();
            _counter = 0;
        }
    }
}

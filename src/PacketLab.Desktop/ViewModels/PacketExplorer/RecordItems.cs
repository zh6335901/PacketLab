using System.Collections;

namespace PacketLab.Desktop.ViewModels.PacketExplorer;

internal sealed class RecordItems(int count, int[]? filtered) : IList
{
    public int Count => filtered?.Length ?? count;
    public bool IsReadOnly => true;
    public bool IsFixedSize => true;
    public bool IsSynchronized => false;
    public object SyncRoot => this;

    internal int RecordAt(int index) => filtered is null ? index : filtered[index];

    public object? this[int index]
    {
        get => (uint)index < (uint)Count ? RecordAt(index) : throw new ArgumentOutOfRangeException(nameof(index));
        set => throw new NotSupportedException();
    }

    public int IndexOf(object? value)
    {
        if (value is not int index)
            return -1;
        if (filtered is null)
            return (uint)index < (uint)count ? index : -1;

        return Math.Max(-1, Array.BinarySearch(filtered, index));
    }

    public bool Contains(object? value) => IndexOf(value) >= 0;
    public IEnumerator GetEnumerator()
    {
        for (var i = 0; i < Count; i++)
            yield return RecordAt(i);
    }

    public void CopyTo(Array array, int index)
    {
        for (var i = 0; i < Count; i++)
            array.SetValue(RecordAt(i), index + i);
    }

    public int Add(object? value) => throw new NotSupportedException();
    public void Insert(int index, object? value) => throw new NotSupportedException();
    public void Remove(object? value) => throw new NotSupportedException();
    public void RemoveAt(int index) => throw new NotSupportedException();
    public void Clear() => throw new NotSupportedException();
}

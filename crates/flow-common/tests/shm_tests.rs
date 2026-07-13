use flow_common::shm::ShmRingBuf;

/// A fixed-size test type for ring buffer operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
struct TestItem {
    id: u64,
    value: [u8; 16],
}

// SAFETY: TestItem is Copy, Clone, and #[repr(C)] — all bit patterns are valid.
unsafe impl flow_common::shm::Pod for TestItem {}

#[test]
fn create_and_push_pop_single_item() {
    let buf = ShmRingBuf::<TestItem>::create("test_single", 16).unwrap();
    let item = TestItem {
        id: 42,
        value: [0xAA; 16],
    };
    assert!(buf.try_push(&item).unwrap());
    let popped = buf.try_pop().unwrap();
    assert_eq!(popped, Some(item));
}

#[test]
fn pop_from_empty_returns_none() {
    let buf = ShmRingBuf::<TestItem>::create("test_empty", 16).unwrap();
    let popped = buf.try_pop().unwrap();
    assert_eq!(popped, None);
}

#[test]
fn fill_and_drain_ring_buffer() {
    let capacity = 8;
    let buf = ShmRingBuf::<TestItem>::create("test_fill", capacity).unwrap();

    // Fill the buffer
    for i in 0..capacity {
        let item = TestItem {
            id: i as u64,
            value: [i as u8; 16],
        };
        assert!(buf.try_push(&item).unwrap(), "push {} should succeed", i);
    }

    // Buffer is full, next push should fail
    let overflow = TestItem {
        id: 999,
        value: [0xFF; 16],
    };
    assert!(!buf.try_push(&overflow).unwrap(), "push on full buffer should return false");

    // Drain the buffer
    for i in 0..capacity {
        let popped = buf.try_pop().unwrap();
        assert_eq!(
            popped,
            Some(TestItem {
                id: i as u64,
                value: [i as u8; 16],
            }),
            "pop {} should match",
            i
        );
    }

    // Buffer is now empty
    assert_eq!(buf.try_pop().unwrap(), None);
}

#[test]
fn open_existing_buffer_reads_data() {
    let name = "test_open";
    let producer = ShmRingBuf::<TestItem>::create(name, 16).unwrap();
    let item = TestItem {
        id: 7,
        value: [0xBB; 16],
    };
    producer.try_push(&item).unwrap();

    // Open the same buffer from a "different" consumer
    let consumer = ShmRingBuf::<TestItem>::open(name).unwrap();
    let popped = consumer.try_pop().unwrap();
    assert_eq!(popped, Some(item));
}

#[test]
fn multiple_producer_consumer_cycles() {
    let buf = ShmRingBuf::<TestItem>::create("test_cycles", 4).unwrap();

    for cycle in 0..10 {
        let item = TestItem {
            id: cycle,
            value: [cycle as u8; 16],
        };
        assert!(buf.try_push(&item).unwrap());
        assert_eq!(buf.try_pop().unwrap(), Some(item));
    }
}
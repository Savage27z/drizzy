use opensea_mint::domain::{ExecutionTiming, PhaseWindow};

#[test]
fn an_open_phase_executes_immediately() {
    let phase = PhaseWindow::new(100, Some(200)).expect("valid phase");

    assert_eq!(phase.execution_timing(150), ExecutionTiming::Immediate);
}

#[test]
fn phase_end_timestamp_is_exclusive() {
    let phase = PhaseWindow::new(100, Some(200)).expect("valid phase");

    assert_eq!(phase.execution_timing(200), ExecutionTiming::Ended);
    assert_eq!(phase.execution_timing(199), ExecutionTiming::Immediate);
}

#[test]
fn an_upcoming_phase_exposes_its_block_timestamp() {
    let phase = PhaseWindow::new(100, Some(200)).expect("valid phase");

    assert_eq!(
        phase.execution_timing(99),
        ExecutionTiming::ScheduledAt(100)
    );
    assert_eq!(phase.starts_at(), 100);
    assert_eq!(phase.ends_at(), Some(200));
}

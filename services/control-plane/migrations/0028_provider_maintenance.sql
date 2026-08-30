ALTER TABLE cloud_provider_state
    DROP CONSTRAINT cloud_provider_state_state_check;

ALTER TABLE cloud_provider_state
    ADD CONSTRAINT cloud_provider_state_state_check CHECK (
        state IN (
            'healthy',
            'credit_blocked',
            'auth_blocked',
            'transient_blocked',
            'permanent_blocked',
            'operator_maintenance'
        )
    );

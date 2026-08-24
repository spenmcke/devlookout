#!/usr/bin/env node
'use strict';

// Upgrade preflight is intentionally read-only. Back up only after this passes,
// then stop the service before changing binaries or running future migrations.
require('./lookout-doctor');

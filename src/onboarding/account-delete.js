'use strict';

async function deleteHostedAccount({ tenantId, userId, setupAuthority, consoleStore, diagnosticsService = null, operationalHealthService = null, supportStore = null, deleteAuthUser } = {}) {
  await setupAuthority.deleteTenant({ tenantId, userId });
  await consoleStore.deleteTenant({ tenantId });
  if (diagnosticsService) await diagnosticsService.deleteTenant(tenantId);
  if (operationalHealthService) await operationalHealthService.deleteTenant(tenantId);
  if (supportStore) await supportStore.deleteTenantSupport(tenantId);
  try {
    await deleteAuthUser(userId);
  } catch (error) {
    const restored = await Promise.allSettled([
      consoleStore.restoreTenantAfterFailedDeletion({ tenantId }),
      setupAuthority.restoreTenantAfterFailedDeletion({ tenantId, userId })
    ]);
    if (restored.some((result) => result.status === 'rejected')) throw new Error('Account deletion failed and its state could not be restored', { cause: error });
    throw error;
  }
  return { deleted: true };
}

module.exports = { deleteHostedAccount };

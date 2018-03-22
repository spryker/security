<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\GlossaryStorage\Communication\Plugin\Event\Listener;

use Spryker\Zed\Glossary\Dependency\GlossaryEvents;
use Spryker\Zed\PropelOrm\Business\Transaction\DatabaseTransactionHandlerTrait;

/**
 * @method \Spryker\Zed\GlossaryStorage\Persistence\GlossaryStorageQueryContainerInterface getQueryContainer()
 * @method \Spryker\Zed\GlossaryStorage\Communication\GlossaryStorageCommunicationFactory getFactory()
 */
class GlossaryKeyStorageListener extends AbstractGlossaryTranslationStorageListener
{
    use DatabaseTransactionHandlerTrait;

    /**
     * @api
     *
     * @param \Spryker\Shared\Kernel\Transfer\TransferInterface[] $eventTransfers
     * @param string $eventName
     *
     * @return void
     */
    public function handleBulk(array $eventTransfers, $eventName)
    {
        $this->preventTransaction();
        $glossaryKeyIds = $this->getFactory()->getEventBehaviorFacade()->getEventTransferIds($eventTransfers);

        if ($eventName === GlossaryEvents::ENTITY_SPY_GLOSSARY_KEY_DELETE ||
            $eventName === GlossaryEvents::GLOSSARY_KEY_UNPUBLISH
        ) {
            $this->unpublish($glossaryKeyIds);
        } else {
            $this->publish($glossaryKeyIds);
        }
    }
}

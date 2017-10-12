<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Sales\Business\OrderProcess;

interface OrderprocessConstant
{
    // STATE
    const STATE_NEW = 'new';

    const STATE_EXPORTABLE = 'exportable';

    const STATE_CLOSED = 'closed';

    const STATE_FINALLY_CLOSED = 'finally closed';

    const STATE_WAITING_FOR_PAYMENT = 'waiting for payment';

    // EVENT
    const EVENT_ON_ENTER = 'onEnter';

    const EVENT_CLOSE = 'close';

    const EVENT_START_INVOICE_CREATION = 'start invoice creation';

    const EVENT_CHECK_DAILY_TIMEOUT = 'check daily timeout';

    const EVENT_CHECK_WEEKLY_TIMEOUT = 'check weekly timeout';

    const EVENT_CHECK_MONTHLY_TIMEOUT = 'check monthly timeout';

    const EVENT_REDIRECT_PAYMENT_CANCELLED_REGULAR = 'redirect payment cancelled regular';

    // CONDITION
    const RULE_ORDER_USED_CODE = 'order used code';
}

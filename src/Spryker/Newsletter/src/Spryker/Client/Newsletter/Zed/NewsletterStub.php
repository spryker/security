<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Client\Newsletter\Zed;

use Generated\Shared\Transfer\NewsletterSubscriberTransfer;
use Generated\Shared\Transfer\NewsletterSubscriptionRequestTransfer;
use Spryker\Client\ZedRequest\ZedRequestClient;

class NewsletterStub implements NewsletterStubInterface
{

    /**
     * @var \Spryker\Client\ZedRequest\ZedRequestClient
     */
    protected $zedStub;

    /**
     * @param \Spryker\Client\ZedRequest\ZedRequestClient $zedStub
     */
    public function __construct(ZedRequestClient $zedStub)
    {
        $this->zedStub = $zedStub;
    }

    /**
     * @param \Generated\Shared\Transfer\NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest
     *
     * @return \Generated\Shared\Transfer\NewsletterSubscriptionResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function subscribeWithSingleOptIn(NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest)
    {
        return $this->zedStub->call('/newsletter/gateway/subscribe-with-single-opt-in', $newsletterSubscriptionRequest);
    }

    /**
     * @param \Generated\Shared\Transfer\NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest
     *
     * @return \Generated\Shared\Transfer\NewsletterSubscriptionResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function subscribeWithDoubleOptIn(NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest)
    {
        return $this->zedStub->call('/newsletter/gateway/subscribe-with-double-opt-in', $newsletterSubscriptionRequest);
    }

    /**
     * @param \Generated\Shared\Transfer\NewsletterSubscriberTransfer $newsletterSubscriber
     *
     * @return \Generated\Shared\Transfer\NewsletterSubscriptionApprovalResultTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function approveDoubleOptInSubscriber(NewsletterSubscriberTransfer $newsletterSubscriber)
    {
        return $this->zedStub->call('/newsletter/gateway/approve-double-opt-in-subscriber', $newsletterSubscriber);
    }

    /**
     * @param \Generated\Shared\Transfer\NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest
     *
     * @return \Generated\Shared\Transfer\NewsletterSubscriptionResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function unsubscribe(NewsletterSubscriptionRequestTransfer $newsletterSubscriptionRequest)
    {
        return $this->zedStub->call('/newsletter/gateway/unsubscribe', $newsletterSubscriptionRequest);
    }

    /**
     * @param \Generated\Shared\Transfer\NewsletterSubscriptionRequestTransfer $newsletterUnsubscriptionRequest
     *
     * @return \Generated\Shared\Transfer\NewsletterSubscriptionResponseTransfer|\Spryker\Shared\Kernel\Transfer\TransferInterface
     */
    public function checkSubscription(NewsletterSubscriptionRequestTransfer $newsletterUnsubscriptionRequest)
    {
        return $this->zedStub->call('/newsletter/gateway/check-subscription', $newsletterUnsubscriptionRequest);
    }

}

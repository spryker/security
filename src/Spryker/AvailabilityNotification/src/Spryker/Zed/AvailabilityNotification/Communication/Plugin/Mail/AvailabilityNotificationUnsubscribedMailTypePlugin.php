<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\AvailabilityNotification\Communication\Plugin\Mail;

use Spryker\Zed\Kernel\Communication\AbstractPlugin;
use Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface;
use Spryker\Zed\Mail\Dependency\Plugin\MailTypePluginInterface;

/**
 * @method \Spryker\Zed\AvailabilityNotification\Business\AvailabilityNotificationFacadeInterface getFacade()
 * @method \Spryker\Zed\AvailabilityNotification\Communication\AvailabilityNotificationCommunicationFactory getFactory()
 * @method \Spryker\Zed\AvailabilityNotification\AvailabilityNotificationConfig getConfig()
 */
class AvailabilityNotificationUnsubscribedMailTypePlugin extends AbstractPlugin implements MailTypePluginInterface
{
    public const AVAILABILITY_NOTIFICATION_UNSUBSCRIBED_MAIL = 'AVAILABILITY_NOTIFICATION_UNSUBSCRIBED_MAIL';

    /**
     * @api
     *
     * @return string
     */
    public function getName(): string
    {
        return static::AVAILABILITY_NOTIFICATION_UNSUBSCRIBED_MAIL;
    }

    /**
     * @api
     *
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return void
     */
    public function build(MailBuilderInterface $mailBuilder): void
    {
        $this
            ->setSubject($mailBuilder)
            ->setHtmlTemplate($mailBuilder)
            ->setTextTemplate($mailBuilder)
            ->setSender($mailBuilder)
            ->setRecipient($mailBuilder);
    }

    /**
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return $this
     */
    protected function setSubject(MailBuilderInterface $mailBuilder): MailTypePluginInterface
    {
        $mailTransfer = $mailBuilder->getMailTransfer();
        $mailTransfer->requireAvailabilitySubscriptionMailData();
        $productName = $mailTransfer
            ->getAvailabilitySubscriptionMailData()
            ->getProductName();
        $mailBuilder->setSubject(
            'availability_subscription.mail.unsubscribed.subject',
            ['%name%' => $productName]
        );

        return $this;
    }

    /**
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return $this
     */
    protected function setHtmlTemplate(MailBuilderInterface $mailBuilder): MailTypePluginInterface
    {
        $mailBuilder->setHtmlTemplate('AvailabilityNotification/mail/unsubscribed.html.twig');

        return $this;
    }

    /**
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return $this
     */
    protected function setTextTemplate(MailBuilderInterface $mailBuilder): MailTypePluginInterface
    {
        $mailBuilder->setTextTemplate('AvailabilityNotification/mail/unsubscribed.text.twig');

        return $this;
    }

    /**
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return $this
     */
    protected function setRecipient(MailBuilderInterface $mailBuilder): MailTypePluginInterface
    {
        $mailTransfer = $mailBuilder->getMailTransfer();
        $mailTransfer->requireAvailabilitySubscriptionMailData();
        $availabilitySubscriptionTransfer = $mailTransfer
            ->getAvailabilitySubscriptionMailData()
            ->requireAvailabilitySubscription()
            ->getAvailabilitySubscription();

        $mailBuilder->addRecipient($availabilitySubscriptionTransfer->getEmail(), '');

        return $this;
    }

    /**
     * @param \Spryker\Zed\Mail\Business\Model\Mail\Builder\MailBuilderInterface $mailBuilder
     *
     * @return $this
     */
    protected function setSender(MailBuilderInterface $mailBuilder): MailTypePluginInterface
    {
        $mailBuilder->setSender('mail.sender.email', 'mail.sender.name');

        return $this;
    }
}

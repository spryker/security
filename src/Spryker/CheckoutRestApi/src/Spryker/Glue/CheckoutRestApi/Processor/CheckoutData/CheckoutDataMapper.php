<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Glue\CheckoutRestApi\Processor\CheckoutData;

use Generated\Shared\Transfer\PaymentMethodsTransfer;
use Generated\Shared\Transfer\RestAddressTransfer;
use Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer;
use Generated\Shared\Transfer\RestCheckoutDataTransfer;
use Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer;
use Generated\Shared\Transfer\RestPaymentMethodTransfer;
use Generated\Shared\Transfer\RestPaymentProviderTransfer;
use Generated\Shared\Transfer\RestShipmentMethodTransfer;
use Spryker\Glue\CheckoutRestApi\CheckoutRestApiConfig;
use Spryker\Glue\CheckoutRestApi\Processor\Exception\PaymentMethodNotConfiguredException;

class CheckoutDataMapper implements CheckoutDataMapperInterface
{
    /**
     * @var \Spryker\Glue\CheckoutRestApi\CheckoutRestApiConfig
     */
    protected $config;

    /**
     * @param \Spryker\Glue\CheckoutRestApi\CheckoutRestApiConfig $config
     */
    public function __construct(CheckoutRestApiConfig $config)
    {
        $this->config = $config;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataTransfer $restCheckoutDataTransfer
     * @param \Generated\Shared\Transfer\RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer
     */
    public function mapRestCheckoutDataTransferToRestCheckoutDataResponseAttributesTransfer(
        RestCheckoutDataTransfer $restCheckoutDataTransfer,
        RestCheckoutRequestAttributesTransfer $restCheckoutRequestAttributesTransfer
    ): RestCheckoutDataResponseAttributesTransfer {
        $restCheckoutDataResponseAttributesTransfer = new RestCheckoutDataResponseAttributesTransfer();

        $restCheckoutDataResponseAttributesTransfer = $this->mapAddresses(
            $restCheckoutDataTransfer,
            $restCheckoutDataResponseAttributesTransfer
        );
        $restCheckoutDataResponseAttributesTransfer = $this->mapPaymentProviders(
            $restCheckoutDataTransfer,
            $restCheckoutDataResponseAttributesTransfer
        );
        $restCheckoutDataResponseAttributesTransfer = $this->mapShipmentMethods(
            $restCheckoutDataTransfer,
            $restCheckoutDataResponseAttributesTransfer
        );

        return $restCheckoutDataResponseAttributesTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataTransfer $restCheckoutDataTransfer
     * @param \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer
     */
    protected function mapAddresses(
        RestCheckoutDataTransfer $restCheckoutDataTransfer,
        RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
    ): RestCheckoutDataResponseAttributesTransfer {
        $addresses = $restCheckoutDataTransfer->getAddresses()->getAddresses();
        foreach ($addresses as $addressTransfer) {
            $restCheckoutDataResponseAttributesTransfer->addAddress(
                (new RestAddressTransfer())->fromArray(
                    $addressTransfer->toArray(),
                    true
                )->setId($addressTransfer->getUuid())
            );
        }

        return $restCheckoutDataResponseAttributesTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataTransfer $checkoutDataTransfer
     * @param \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer
     */
    protected function mapPaymentProviders(
        RestCheckoutDataTransfer $checkoutDataTransfer,
        RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
    ): RestCheckoutDataResponseAttributesTransfer {
        $availablePaymentMethodsList = $this->getAvailablePaymentMethodsList($checkoutDataTransfer->getAvailablePaymentMethods());
        $paymentProviders = $checkoutDataTransfer->getPaymentProviders()->getPaymentProviders();
        foreach ($paymentProviders as $paymentProviderTransfer) {
            $restPaymentProviderTransfer = new RestPaymentProviderTransfer();
            $restPaymentProviderTransfer->setPaymentProviderName($paymentProviderTransfer->getName());

            foreach ($paymentProviderTransfer->getPaymentMethods() as $paymentMethodTransfer) {
                $paymentSelection = $this->getPaymentSelectionByPaymentProviderAndMethodNames($restPaymentProviderTransfer->getPaymentProviderName(), $paymentMethodTransfer->getMethodName());
                if (in_array($paymentSelection, $availablePaymentMethodsList)) {
                    $restPaymentMethodTransfer = (new RestPaymentMethodTransfer())
                        ->setPaymentMethodName($paymentMethodTransfer->getMethodName());
                    $restPaymentMethodTransfer->setRequiredRequestData($this->config->getRequiredRequestDataForPaymentMethod($paymentSelection));
                    $restPaymentProviderTransfer->addPaymentMethod($restPaymentMethodTransfer);
                }
            }
            $restCheckoutDataResponseAttributesTransfer->addPaymentProvider($restPaymentProviderTransfer);
        }

        return $restCheckoutDataResponseAttributesTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\RestCheckoutDataTransfer $checkoutDataTransfer
     * @param \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
     *
     * @return \Generated\Shared\Transfer\RestCheckoutDataResponseAttributesTransfer
     */
    protected function mapShipmentMethods(
        RestCheckoutDataTransfer $checkoutDataTransfer,
        RestCheckoutDataResponseAttributesTransfer $restCheckoutDataResponseAttributesTransfer
    ): RestCheckoutDataResponseAttributesTransfer {
        $shipmentMethods = $checkoutDataTransfer->getShipmentMethods()->getMethods();
        foreach ($shipmentMethods as $shipmentMethodTransfer) {
            $restShipmentMethodTransfer = new RestShipmentMethodTransfer();
            $restShipmentMethodTransfer->fromArray($shipmentMethodTransfer->toArray(), true)
                ->setPrice($shipmentMethodTransfer->getStoreCurrencyPrice())
                ->setId($shipmentMethodTransfer->getIdShipmentMethod());

            $restCheckoutDataResponseAttributesTransfer->addShipmentMethod($restShipmentMethodTransfer);
        }

        return $restCheckoutDataResponseAttributesTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\PaymentMethodsTransfer $availablePaymentMethods
     *
     * @return array
     */
    protected function getAvailablePaymentMethodsList(PaymentMethodsTransfer $availablePaymentMethods): array
    {
        $availablePaymentMethodsList = [];
        foreach ($availablePaymentMethods->getMethods() as $paymentMethodTransfer) {
            $availablePaymentMethodsList[] = $paymentMethodTransfer->getMethodName();
        }

        return $availablePaymentMethodsList;
    }

    /**
     * @param string $paymentProviderName
     * @param string $paymentMethodName
     *
     * @throws \Spryker\Glue\CheckoutRestApi\Processor\Exception\PaymentMethodNotConfiguredException
     *
     * @return string
     */
    protected function getPaymentSelectionByPaymentProviderAndMethodNames(string $paymentProviderName, string $paymentMethodName): string
    {
        $paymentProviderMethodToStateMachineMapping = $this->config->getPaymentProviderMethodToStateMachineMapping();

        if (!isset($paymentProviderMethodToStateMachineMapping[$paymentProviderName][$paymentMethodName])) {
            throw new PaymentMethodNotConfiguredException(sprintf(
                'Payment method "%s" for payment provider "%s" is not configured in CheckoutRestApiConfig::getPaymentProviderMethodToStateMachineMapping()',
                $paymentMethodName,
                $paymentProviderName
            ));
        }

        return $paymentProviderMethodToStateMachineMapping[$paymentProviderName][$paymentMethodName];
    }
}

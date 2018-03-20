<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ManualOrderEntryGui\Communication\Form\DataProvider;

use Generated\Shared\Transfer\AddressTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Spryker\Zed\ManualOrderEntryGui\Communication\Form\Address\AddressCollectionType;
use Spryker\Zed\ManualOrderEntryGui\Dependency\Service\ManualOrderEntryGuiToStoreInterface;

class AddressCollectionDataProvider implements FormDataProviderInterface
{

    /**
     * @var \Spryker\Zed\ManualOrderEntryGui\Dependency\Service\ManualOrderEntryGuiToStoreInterface
     */
    protected $store;

    /**
     * @var \Generated\Shared\Transfer\CustomerTransfer
     */
    protected $customerTransfer;

    /**
     * @param \Spryker\Zed\ManualOrderEntryGui\Dependency\Service\ManualOrderEntryGuiToStoreInterface $store
     */
    public function __construct(ManualOrderEntryGuiToStoreInterface $store)
    {
        $this->store = $store;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Spryker\Shared\Kernel\Transfer\AbstractTransfer
     */
    public function getData($quoteTransfer)
    {
        $this->customerTransfer = $quoteTransfer->getCustomer();

        $quoteTransfer->setShippingAddress($this->getShippingAddress($quoteTransfer));
        $quoteTransfer->setBillingAddress($this->getBillingAddress($quoteTransfer));

        if ($quoteTransfer->getBillingAddress()->toArray() == $quoteTransfer->getShippingAddress()->toArray()) {
            $quoteTransfer->setBillingSameAsShipping(true);
        }

        return $quoteTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return array
     */
    public function getOptions($quoteTransfer)
    {
        return [
            'data_class' => QuoteTransfer::class,
            'allow_extra_fields' => true,
            'csrf_protection' => false,
            AddressCollectionType::OPTION_ADDRESS_CHOICES => $this->getAddressChoices(),
            AddressCollectionType::OPTION_COUNTRY_CHOICES => $this->getAvailableCountries(),
        ];
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\AddressTransfer
     */
    protected function getShippingAddress(QuoteTransfer $quoteTransfer)
    {
        $shippingAddressTransfer = new AddressTransfer();
        if ($quoteTransfer->getShippingAddress() !== null) {
            $shippingAddressTransfer = $quoteTransfer->getShippingAddress();
        }

        if ($this->customerTransfer !== null && $quoteTransfer->getShippingAddress() === null) {
            $shippingAddressTransfer->setIdCustomerAddress($this->customerTransfer->getDefaultShippingAddress());
        }

        return $shippingAddressTransfer;
    }

    /**
     * @param \Generated\Shared\Transfer\QuoteTransfer $quoteTransfer
     *
     * @return \Generated\Shared\Transfer\AddressTransfer
     */
    protected function getBillingAddress(QuoteTransfer $quoteTransfer)
    {
        $billingAddressTransfer = new AddressTransfer();
        if ($quoteTransfer->getBillingAddress() !== null) {
            $billingAddressTransfer = $quoteTransfer->getBillingAddress();
        }

        if ($this->customerTransfer !== null && $quoteTransfer->getBillingAddress() === null) {
            $billingAddressTransfer->setIdCustomerAddress($this->customerTransfer->getDefaultBillingAddress());
        }

        return $billingAddressTransfer;
    }

    /**
     * @return array
     */
    protected function getAddressChoices()
    {
        if ($this->customerTransfer === null) {
            return [];
        }

        $customerAddressesTransfer = $this->customerTransfer->getAddresses();

        if ($customerAddressesTransfer === null) {
            return [];
        }

        $choices = [];
        foreach ($customerAddressesTransfer->getAddresses() as $address) {
            $choices[$address->getIdCustomerAddress()] = sprintf(
                '%s %s %s, %s %s, %s %s',
                $address->getSalutation(),
                $address->getFirstName(),
                $address->getLastName(),
                $address->getAddress1(),
                $address->getAddress2(),
                $address->getZipCode(),
                $address->getCity()
            );
        }

        return $choices;
    }

    /**
     * @return array
     */
    protected function getAvailableCountries()
    {
        $countries = [];

        foreach ($this->store->getCountries() as $iso2Code) {
            $countries[$iso2Code] = $iso2Code;
        }

        return $countries;
    }
}

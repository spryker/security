<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Country\Business;

use Spryker\Zed\Kernel\Business\AbstractFacade;

/**
 * @method \Spryker\Zed\Country\Business\CountryBusinessFactory getFactory()
 */
class CountryFacade extends AbstractFacade implements CountryFacadeInterface
{
    /**
     * @api
     *
     * @return void
     */
    public function install()
    {
        $this->getFactory()->createInstaller()->install();
    }

    /**
     * @api
     *
     * @param string $iso2Code
     *
     * @return bool
     */
    public function hasCountry($iso2Code)
    {
        return $this->getFactory()->createCountryManager()->hasCountry($iso2Code);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @deprecated Use getCountryByIso2Code() instead.
     *
     * @param string $iso2Code
     *
     * @return int
     */
    public function getIdCountryByIso2Code($iso2Code)
    {
        return $this->getFactory()->createCountryManager()->getIdCountryByIso2Code($iso2Code);
    }

    /**
     * {@inheritdoc}
     *
     * @api
     *
     * @param string $iso2Code
     *
     * @return \Generated\Shared\Transfer\CountryTransfer
     */
    public function getCountryByIso2Code($iso2Code)
    {
        return $this->getFactory()->createCountryManager()->getCountryByIso2Code($iso2Code);
    }

    /**
     * @api
     *
     * @param string $iso3Code
     *
     * @return \Generated\Shared\Transfer\CountryTransfer
     */
    public function getCountryByIso3Code($iso3Code)
    {
        return $this->getFactory()->createCountryManager()->getCountryByIso3Code($iso3Code);
    }

    /**
     * @api
     *
     * @return \Generated\Shared\Transfer\CountryCollectionTransfer
     */
    public function getAvailableCountries()
    {
        $countries = $this->getFactory()
            ->createCountryManager()
            ->getCountryCollection();

        return $countries;
    }

    /**
     * @api
     *
     * @param string $countryName
     *
     * @return \Generated\Shared\Transfer\CountryTransfer
     */
    public function getPreferredCountryByName($countryName)
    {
        $countryTransfer = $this->getFactory()
            ->createCountryManager()
            ->getPreferredCountryByName($countryName);

        return $countryTransfer;
    }
}

<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\Locale\Business\Manager;

use Orm\Zed\Locale\Persistence\SpyLocale;
use Spryker\Shared\Kernel\Store;
use Spryker\Zed\Locale\Business\Exception\LocaleExistsException;
use Spryker\Zed\Locale\Business\Exception\MissingLocaleException;
use Spryker\Zed\Locale\Business\TransferGeneratorInterface;
use Spryker\Zed\Locale\Persistence\LocaleQueryContainerInterface;

class LocaleManager
{
    /**
     * @var \Spryker\Zed\Locale\Persistence\LocaleQueryContainerInterface
     */
    protected $localeQueryContainer;

    /**
     * @var \Spryker\Zed\Locale\Business\TransferGeneratorInterface
     */
    protected $transferGenerator;

    /**
     * @param \Spryker\Zed\Locale\Persistence\LocaleQueryContainerInterface $localeQueryContainer
     * @param \Spryker\Zed\Locale\Business\TransferGeneratorInterface $transferGenerator
     */
    public function __construct(
        LocaleQueryContainerInterface $localeQueryContainer,
        TransferGeneratorInterface $transferGenerator
    ) {
        $this->localeQueryContainer = $localeQueryContainer;
        $this->transferGenerator = $transferGenerator;
    }

    /**
     * @param string $localeName
     *
     * @throws \Spryker\Zed\Locale\Business\Exception\MissingLocaleException
     *
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    public function getLocale($localeName)
    {
        $localeQuery = $this->localeQueryContainer->queryLocaleByName($localeName);
        $locale = $localeQuery->findOne();
        if (!$locale) {
            throw new MissingLocaleException(
                sprintf(
                    'Tried to retrieve locale %s, but it does not exist',
                    $localeName
                )
            );
        }

        return $this->transferGenerator->convertLocale($locale);
    }

    /**
     * @deprecated Use getLocale($localeName) instead
     *
     * @param string $localeCode
     *
     * @throws \Spryker\Zed\Locale\Business\Exception\MissingLocaleException
     *
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    public function getLocaleByCode($localeCode)
    {
        $locales = $this->getLocaleCollection();

        if (!array_key_exists($localeCode, $locales)) {
            throw new MissingLocaleException(
                sprintf(
                    'Tried to retrieve locale with code %s, but it does not exist',
                    $localeCode
                )
            );
        }

        return $locales[$localeCode];
    }

    /**
     * @param int $idLocale
     *
     * @throws \Spryker\Zed\Locale\Business\Exception\MissingLocaleException
     *
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    public function getLocaleById($idLocale)
    {
        $localeEntity = $this->localeQueryContainer
            ->queryLocales()
            ->filterByIdLocale($idLocale)
            ->findOne();

        if (!$localeEntity) {
            throw new MissingLocaleException(
                sprintf(
                    'Tried to retrieve locale with id %s, but it does not exist',
                    $idLocale
                )
            );
        }

        return $this->transferGenerator->convertLocale($localeEntity);
    }

    /**
     * @param string $localeName
     *
     * @throws \Spryker\Zed\Locale\Business\Exception\LocaleExistsException
     *
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    public function createLocale($localeName)
    {
        if ($this->hasLocale($localeName)) {
            throw new LocaleExistsException(
                sprintf(
                    'Tried to create locale %s, but it already exists',
                    $localeName
                )
            );
        }

        $locale = new SpyLocale();
        $locale->setLocaleName($localeName);

        $locale->save();

        return $this->transferGenerator->convertLocale($locale);
    }

    /**
     * @param string $localeName
     *
     * @return bool
     */
    public function hasLocale($localeName)
    {
        $localeQuery = $this->localeQueryContainer->queryLocaleByName($localeName);

        return $localeQuery->count() > 0;
    }

    /**
     * @param string $localeName
     *
     * @return bool
     */
    public function deleteLocale($localeName)
    {
        if (!$this->hasLocale($localeName)) {
            return true;
        }

        $locale = $this->localeQueryContainer
            ->queryLocaleByName($localeName)
            ->findOne();

        $locale->setIsActive(false);
        $locale->save();

        return true;
    }

    /**
     * @return \Generated\Shared\Transfer\LocaleTransfer[]
     */
    public function getLocaleCollection()
    {
        $availableLocales = Store::getInstance()->getLocales();

        $transferCollection = [];
        foreach ($availableLocales as $localeName) {
            $localeInfo = $this->getLocale($localeName);
            $transferCollection[$localeInfo->getLocaleName()] = $localeInfo;
        }

        return $transferCollection;
    }

    /**
     * @api
     *
     * @return array
     */
    public function getAvailableLocales()
    {
        $availableLocales = Store::getInstance()->getLocales();
        $locales = [];
        foreach ($availableLocales as $localeName) {
            $localeInfo = $this->getLocale($localeName);
            $locales[$localeInfo->getIdLocale()] = $localeInfo->getLocaleName();
        }

        return $locales;
    }
}

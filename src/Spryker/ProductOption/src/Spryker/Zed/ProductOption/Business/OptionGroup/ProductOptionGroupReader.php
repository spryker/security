<?php
/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductOption\Business\OptionGroup;

use ArrayObject;
use Generated\Shared\Transfer\ProductOptionGroupTransfer;
use Generated\Shared\Transfer\ProductOptionTranslationTransfer;
use Generated\Shared\Transfer\ProductOptionValueTransfer;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionGroup;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionValue;
use Spryker\Zed\ProductOption\Business\Exception\ProductOptionGroupNotFoundException;
use Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToGlossaryInterface;
use Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToLocaleInterface;
use Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface;

class ProductOptionGroupReader implements ProductOptionGroupReaderInterface
{
    /**
     * @var \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface
     */
    protected $productOptionQueryContainer;

    /**
     * @var \Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToGlossaryInterface
     */
    protected $glossaryFacade;

    /**
     * @var \Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToLocaleInterface
     */
    protected $localeFacade;

    /**
     * @param \Spryker\Zed\ProductOption\Persistence\ProductOptionQueryContainerInterface $productOptionQueryContainer
     * @param \Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToGlossaryInterface $glossaryFacade
     * @param \Spryker\Zed\ProductOption\Dependency\Facade\ProductOptionToLocaleInterface $localeFacade
     */
    public function __construct(
        ProductOptionQueryContainerInterface $productOptionQueryContainer,
        ProductOptionToGlossaryInterface $glossaryFacade,
        ProductOptionToLocaleInterface $localeFacade
    ) {
        $this->productOptionQueryContainer = $productOptionQueryContainer;
        $this->glossaryFacade = $glossaryFacade;
        $this->localeFacade = $localeFacade;
    }

    /**
     * @param int $idProductOptionGroup
     *
     * @throws \Spryker\Zed\ProductOption\Business\Exception\ProductOptionGroupNotFoundException
     *
     * @return \Generated\Shared\Transfer\ProductOptionGroupTransfer
     */
    public function getProductOptionGroupById($idProductOptionGroup)
    {
        $productOptionGroupEntity = $this->queryProductGroupById($idProductOptionGroup);

        if (!$productOptionGroupEntity) {
            throw new ProductOptionGroupNotFoundException(
                sprintf(
                    'Product option group with id "%d" not found.',
                    $idProductOptionGroup
                )
            );
        }

        return $this->hydrateProductOptionGroupTransfer($productOptionGroupEntity);
    }

    /**
     * @param \Orm\Zed\ProductOption\Persistence\SpyProductOptionGroup $productOptionGroupEntity
     *
     * @return \Generated\Shared\Transfer\ProductOptionGroupTransfer
     */
    protected function hydrateProductOptionGroupTransfer(SpyProductOptionGroup $productOptionGroupEntity)
    {
        $productOptionGroupTransfer = new ProductOptionGroupTransfer();
        $productOptionGroupTransfer->fromArray($productOptionGroupEntity->toArray(), true);

        $availableLocales = $this->localeFacade->getLocaleCollection();

        $productOptionValueTranslations = $this->hydrateProductOptionValues(
            $productOptionGroupEntity,
            $productOptionGroupTransfer,
            $availableLocales
        );

        $productOptionGroupTransfer->setProductOptionValueTranslations(new ArrayObject($productOptionValueTranslations));

        $groupNameTranslations = $this->getOptionTranslations(
            $availableLocales,
            $productOptionGroupTransfer->getName(),
            $this->createRelatedKeyHash($productOptionGroupTransfer->getName())
        );

        $productOptionGroupTransfer->setGroupNameTranslations(new ArrayObject($groupNameTranslations));

        return $productOptionGroupTransfer;
    }

    /**
     * @param array $availableLocales
     * @param string $translationKey
     * @param string $relatedOptionHash
     *
     * @return array
     */
    protected function getOptionTranslations(array $availableLocales, $translationKey, $relatedOptionHash)
    {
        $translations = [];
        foreach ($availableLocales as $localeTransfer) {
            if (!$this->glossaryFacade->hasTranslation($translationKey, $localeTransfer)) {
                continue;
            }

            $translationTransfer = $this->glossaryFacade->getTranslation($translationKey, $localeTransfer);

            $productOptionTranslationTransfer = new ProductOptionTranslationTransfer();
            $productOptionTranslationTransfer->setName($translationTransfer->getValue());
            $productOptionTranslationTransfer->setKey($translationKey);
            $productOptionTranslationTransfer->setLocaleCode($localeTransfer->getLocaleName());
            $productOptionTranslationTransfer->setRelatedOptionHash($relatedOptionHash);

            $translations[] = $productOptionTranslationTransfer;
        }

        return $translations;
    }

    /**
     * @param int $identifier
     *
     * @return string
     */
    protected function createRelatedKeyHash($identifier)
    {
        return hash('sha256', $identifier);
    }

    /**
     * @param \Orm\Zed\ProductOption\Persistence\SpyProductOptionGroup $productOptionGroupEntity
     * @param \Generated\Shared\Transfer\ProductOptionGroupTransfer $productOptionGroupTransfer
     * @param array $availableLocales
     *
     * @return array
     */
    protected function hydrateProductOptionValues(
        SpyProductOptionGroup $productOptionGroupEntity,
        ProductOptionGroupTransfer $productOptionGroupTransfer,
        array $availableLocales
    ) {
        $productOptionValueTranslations = [];
        foreach ($productOptionGroupEntity->getSpyProductOptionValues() as $productOptionValueEntity) {
            $productOptionValueTransfer = $this->hydrateProductOptionValueTransfer($productOptionValueEntity);

            $relatedOptionHash = $this->createRelatedKeyHash($productOptionValueEntity->getIdProductOptionValue());
            $productOptionValueTransfer->setOptionHash($relatedOptionHash);

            $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

            $valueTranslations = $this->getOptionTranslations(
                $availableLocales,
                $productOptionValueTransfer->getValue(),
                $relatedOptionHash
            );

            $productOptionValueTranslations = array_merge($productOptionValueTranslations, $valueTranslations);
        }
        return $productOptionValueTranslations;
    }

    /**
     * @param \Orm\Zed\ProductOption\Persistence\SpyProductOptionValue $productOptionValueEntity
     *
     * @return \Generated\Shared\Transfer\ProductOptionValueTransfer
     */
    protected function hydrateProductOptionValueTransfer(SpyProductOptionValue $productOptionValueEntity)
    {
        $productOptionValueTransfer = new ProductOptionValueTransfer();
        $productOptionValueTransfer->fromArray($productOptionValueEntity->toArray(), true);

        return $productOptionValueTransfer;
    }

    /**
     * @param int $idProductOptionGroup
     *
     * @return \Orm\Zed\ProductOption\Persistence\SpyProductOptionGroup
     */
    protected function queryProductGroupById($idProductOptionGroup)
    {
        $productOptionGroupEntity = $this->productOptionQueryContainer
            ->queryProductOptionGroupById($idProductOptionGroup)
            ->findOne();

        return $productOptionGroupEntity;
    }
}

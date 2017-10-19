<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace Spryker\Zed\ProductCategory\Communication;

use Generated\Shared\Transfer\LocaleTransfer;
use Spryker\Zed\Kernel\Communication\AbstractCommunicationFactory;
use Spryker\Zed\ProductCategory\Communication\Form\AssignForm;
use Spryker\Zed\ProductCategory\Communication\Table\ProductCategoryTable;
use Spryker\Zed\ProductCategory\Communication\Table\ProductTable;
use Spryker\Zed\ProductCategory\ProductCategoryDependencyProvider;

/**
 * @method \Spryker\Zed\ProductCategory\Persistence\ProductCategoryQueryContainer getQueryContainer()
 * @method \Spryker\Zed\ProductCategory\ProductCategoryConfig getConfig()
 */
class ProductCategoryCommunicationFactory extends AbstractCommunicationFactory
{
    /**
     * @return \Generated\Shared\Transfer\LocaleTransfer
     */
    public function getCurrentLocale()
    {
        return $this->getLocaleFacade()
            ->getCurrentLocale();
    }

    /**
     * @return \Spryker\Zed\ProductCategory\Dependency\Facade\ProductCategoryToLocaleInterface
     */
    public function getLocaleFacade()
    {
        return $this->getProvidedDependency(ProductCategoryDependencyProvider::FACADE_LOCALE);
    }

    /**
     * @return \Spryker\Zed\ProductCategory\Dependency\QueryContainer\ProductCategoryToCategoryInterface
     */
    public function getCategoryQueryContainer()
    {
        return $this->getProvidedDependency(ProductCategoryDependencyProvider::CATEGORY_QUERY_CONTAINER);
    }

    /**
     * @param \Generated\Shared\Transfer\LocaleTransfer $locale
     * @param int $idCategory
     *
     * @return \Spryker\Zed\ProductCategory\Communication\Table\ProductCategoryTable
     */
    public function createProductCategoryTable(LocaleTransfer $locale, $idCategory)
    {
        return new ProductCategoryTable($this->getQueryContainer(), $this->getUtilEncodingService(), $locale, $idCategory);
    }

    /**
     * @param \Generated\Shared\Transfer\LocaleTransfer $locale
     * @param int $idCategory
     *
     * @return \Spryker\Zed\ProductCategory\Communication\Table\ProductTable
     */
    public function createProductTable(LocaleTransfer $locale, $idCategory)
    {
        return new ProductTable($this->getQueryContainer(), $this->getUtilEncodingService(), $locale, $idCategory);
    }

    /**
     * @return \Spryker\Zed\ProductCategory\Dependency\Service\ProductCategoryToUtilEncodingInterface
     */
    public function getUtilEncodingService()
    {
        return $this->getProvidedDependency(ProductCategoryDependencyProvider::SERVICE_UTIL_ENCODING);
    }

    /**
     * @param array $data
     *
     * @return \Symfony\Component\Form\FormInterface
     */
    public function createAssignForm(array $data)
    {
        $formType = new AssignForm();

        return $this->getFormFactory()->create($formType, $data, []);
    }
}

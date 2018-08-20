<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\ProductOption\Business;

use ArrayObject;
use Codeception\Test\Unit;
use Generated\Shared\Transfer\ItemTransfer;
use Generated\Shared\Transfer\MoneyValueTransfer;
use Generated\Shared\Transfer\ProductOptionCriteriaTransfer;
use Generated\Shared\Transfer\ProductOptionGroupTransfer;
use Generated\Shared\Transfer\ProductOptionTransfer;
use Generated\Shared\Transfer\ProductOptionTranslationTransfer;
use Generated\Shared\Transfer\ProductOptionValueStorePricesRequestTransfer;
use Generated\Shared\Transfer\ProductOptionValueTransfer;
use Generated\Shared\Transfer\QuoteTransfer;
use Orm\Zed\ProductOption\Persistence\SpyProductOptionGroupQuery;
use Spryker\Shared\Price\PriceConfig;
use Spryker\Shared\ProductOption\ProductOptionConstants;
use Spryker\Zed\Currency\Business\CurrencyFacade;
use Spryker\Zed\ProductOption\Business\ProductOptionFacade;
use Spryker\Zed\Store\Business\StoreFacade;
use SprykerTest\Shared\ProductOption\Helper\ProductOptionGroupDataHelper;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group ProductOption
 * @group Business
 * @group Facade
 * @group ProductOptionFacadeTest
 * Add your own group annotations below this line
 */
class ProductOptionFacadeTest extends Unit
{
    const DEFAULT_LOCALE_ISO_CODE = 'en_US';

    const DEFAULT_ID_CURRENCY = 5;
    const DEFAULT_ID_STORE = null;
    const DEFAULT_NET_PRICE = 100;
    const DEFAULT_GROSS_PRICE = 200;

    /**
     * @var \SprykerTest\Zed\ProductOption\ProductOptionBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function testSaveProductOptionGroupShouldPersistProvidedOption()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $idOfProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfProductOptionGroup);

        $this->assertNotEmpty($idOfProductOptionGroup);
        $this->assertEquals($productOptionGroupTransfer->getName(), $productOptionGroupEntity->getName());
        $this->assertSame($productOptionGroupTransfer->getActive(), $productOptionGroupEntity->getActive());

        $productOptionValues = $productOptionGroupEntity->getSpyProductOptionValues();
        $productOptionValueEntity = $productOptionValues[0];

        $this->assertEquals($productOptionValueTransfer->getValue(), $productOptionValueEntity->getValue());
        $this->assertEquals($productOptionValueTransfer->getSku(), $productOptionValueEntity->getSku());
    }

    /**
     * @return void
     */
    public function testSaveProductOptionGroupUpdatesCurrencyPrices()
    {
        // Assign
        $expectedNetResult = 5;
        $expectedGrossResult = 6;
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);
        $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionValueTransfer->setPrices(new ArrayObject());
        $this->tester->addPrice(
            $productOptionValueTransfer,
            static::DEFAULT_ID_STORE,
            static::DEFAULT_ID_CURRENCY,
            $expectedNetResult,
            $expectedGrossResult
        );

        // Act
        $idProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        // Assert
        $productOptionPriceEntity = $this->tester->getFirstProductOptionValuePriceByIdProductOptionGroup($idProductOptionGroup);
        $actualNetPrice = $productOptionPriceEntity->getNetPrice();
        $actualGrossPrice = $productOptionPriceEntity->getGrossPrice();

        $this->assertSame($expectedNetResult, $actualNetPrice);
        $this->assertSame($expectedGrossResult, $actualGrossPrice);
    }

    /**
     * @return void
     */
    public function testSaveProductOptionGroupInsertsNewCurrencyPrices()
    {
        // Assign
        $expectedNetResult = static::DEFAULT_NET_PRICE;
        $expectedGrossResult = static::DEFAULT_GROSS_PRICE;
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        // Act
        $idProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        // Assert
        $productOptionPriceEntity = $this->tester->getFirstProductOptionValuePriceByIdProductOptionGroup($idProductOptionGroup);
        $actualNetPrice = $productOptionPriceEntity->getNetPrice();
        $actualGrossPrice = $productOptionPriceEntity->getGrossPrice();

        $this->assertSame($expectedNetResult, $actualNetPrice);
        $this->assertSame($expectedGrossResult, $actualGrossPrice);
    }

    /**
     * @return void
     */
    public function testSaveProductGroupOptionAndAssignProductAbstract()
    {
        $this->markTestSkipped('ProductAbstract not assigned');

        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $productAbstractEntity = $this->tester->createProductAbstract('testingSku');

        $productOptionGroupTransfer->setProductsToBeAssigned([$productAbstractEntity->getIdProductAbstract()]);

        $idOfProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfProductOptionGroup);

        $assignedProductAbstractEntity = $productOptionGroupEntity->getSpyProductAbstracts()[0];

        $this->assertEquals($assignedProductAbstractEntity->getSku(), $productAbstractEntity->getSku());
    }

    /**
     * @return void
     */
    public function testSaveProductGroupOptionAndDeAssignProductAbstract()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $productAbstractEntity = $this->tester->createProductAbstract('testingSku');

        $productOptionGroupTransfer->setProductsToBeAssigned([$productAbstractEntity->getIdProductAbstract()]);

        $idOfProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupTransfer->setProductsToBeAssigned([]);
        $productOptionGroupTransfer->setProductsToBeDeAssigned([$productAbstractEntity->getIdProductAbstract()]);

        $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfProductOptionGroup);

        $this->assertEmpty($productOptionGroupEntity->getSpyProductAbstracts());
    }

    /**
     * @return void
     */
    public function testSaveProductGroupOptionAndRemoveProductOptionValues()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $productAbstractEntity = $this->tester->createProductAbstract('testingSku');

        $productOptionGroupTransfer->setProductsToBeAssigned([$productAbstractEntity->getIdProductAbstract()]);

        $idOfProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupTransfer->setProductsToBeAssigned([]);
        $productOptionGroupTransfer->setProductOptionValuesToBeRemoved([$productOptionValueTransfer->getIdProductOptionValue()]);

        $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfProductOptionGroup);

        $this->assertEmpty($productOptionGroupEntity->getSpyProductOptionValues());
    }

    /**
     * @return void
     */
    public function testSaveProductOptionValuePersistsOption()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer();

        $idProductOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionValueTransfer->setFkProductOptionGroup($idProductOptionGroup);

        $idProductOptionValue = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        $this->assertNotEmpty($idProductOptionGroup);

        $productOptionValueEntity = $this->tester->findOneProductOptionValueById($idProductOptionValue);

        $this->assertEquals($productOptionValueTransfer->getSku(), $productOptionValueEntity->getSku());
        $this->assertEquals($productOptionValueTransfer->getValue(), $productOptionValueEntity->getValue());
    }

    /**
     * @return void
     */
    public function testSaveProductOptionValueUpdatesCurrencyPrices()
    {
        // Assign
        $expectedNetResult = 5;
        $expectedGrossResult = 6;
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionValueTransfer->setFkProductOptionGroup($this->tester->haveProductOptionGroup()->getIdProductOptionGroup());
        $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        $productOptionValueTransfer->setPrices(new ArrayObject());
        $this->tester->addPrice(
            $productOptionValueTransfer,
            static::DEFAULT_ID_STORE,
            static::DEFAULT_ID_CURRENCY,
            $expectedNetResult,
            $expectedGrossResult
        );

        // Act
        $idProductOptionValue = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        // Assert
        $productOptionPriceEntity = $this->tester->getFirstProductOptionValuePriceByIdProductOptionValue($idProductOptionValue);
        $actualNetPrice = $productOptionPriceEntity->getNetPrice();
        $actualGrossPrice = $productOptionPriceEntity->getGrossPrice();

        $this->assertSame($expectedNetResult, $actualNetPrice);
        $this->assertSame($expectedGrossResult, $actualGrossPrice);
    }

    /**
     * @return void
     */
    public function testSaveProductOptionValueInsertsNewCurrencyPrices()
    {
        // Assign
        $expectedNetResult = static::DEFAULT_NET_PRICE;
        $expectedGrossResult = static::DEFAULT_GROSS_PRICE;
        $productOptionFacade = $this->createProductOptionFacade();
        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionValueTransfer->setFkProductOptionGroup($this->tester->haveProductOptionGroup()->getIdProductOptionGroup());

        // Act
        $idProductOptionValue = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        // Assert
        $productOptionPriceEntity = $this->tester->getFirstProductOptionValuePriceByIdProductOptionValue($idProductOptionValue);
        $actualNetPrice = $productOptionPriceEntity->getNetPrice();
        $actualGrossPrice = $productOptionPriceEntity->getGrossPrice();

        $this->assertSame($expectedNetResult, $actualNetPrice);
        $this->assertSame($expectedGrossResult, $actualGrossPrice);
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueShouldReturnPersistedOptionValue()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $idOfPersistedOptionValue = $productOptionValueTransfer->getIdProductOptionValue();

        $productOptionTransfer = $productOptionFacade->getProductOptionValueById($idOfPersistedOptionValue);

        $this->assertEquals($idOfPersistedOptionValue, $productOptionTransfer->getIdProductOptionValue());
        $this->assertEquals($productOptionValueTransfer->getValue(), $productOptionTransfer->getValue());
        $this->assertEquals($productOptionValueTransfer->getSku(), $productOptionTransfer->getSku());
    }

    /**
     * @return void
     */
    public function testGetProductOptionByIdShouldReturnPersistedOptionGroup()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $idOfPersistedOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $persistedProductOptionGroupTransfer = $productOptionFacade->getProductOptionGroupById($idOfPersistedOptionGroup);

        $this->assertNotEmpty($persistedProductOptionGroupTransfer);
        $this->assertEquals($productOptionGroupTransfer->getName(), $persistedProductOptionGroupTransfer->getName());
    }

    /**
     * @return void
     */
    public function testGetProductOptionGroupByIdReturnsAllCurrencies()
    {
        // Assign
        $productOptionGroupTransfer = $this->tester->haveProductOptionGroupWithValues(
            [],
            [
                [
                    [],
                    [
                        [ProductOptionGroupDataHelper::CURRENCY_CODE => 'EUR'],
                        [ProductOptionGroupDataHelper::CURRENCY_CODE => 'USD'],
                    ],
                ],
            ]
        );

        $expectedCurrencies = ['EUR', 'USD'];

        // Act
        $this->tester->enablePropelInstancePooling(); // JoinWith needs it to populate all 3rd level joinWith records
        $actualProductGroupOption = $this->createProductOptionFacade()->getProductOptionGroupById($productOptionGroupTransfer->getIdProductOptionGroup());

        // Assert
        $actualCurrencies = array_map(
            function (MoneyValueTransfer $moneyValueTransfer) {
                return $moneyValueTransfer->getCurrency()->getCode();
            },
            $actualProductGroupOption->getProductOptionValues()[0]->getPrices()->getArrayCopy()
        );

        $this->assertEquals($expectedCurrencies, $actualCurrencies);
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueByIdReturnsRequestCurrencyAndStorePrices()
    {
        // Assign
        $expectedGrossAmount = 1144;
        $expectedNetAmount = 2233;

        $this->mockStoreFacadeDefaultStore('DE');
        $this->mockCurrencyFacadeDefaultCurrency('USD');

        $productOptionGroupTransfer = $this->tester->haveProductOptionGroupWithValues(
            [],
            [
                [
                    [],
                    [
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'EUR',
                            ProductOptionGroupDataHelper::STORE_NAME => 'DE',
                        ],
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'USD',
                            ProductOptionGroupDataHelper::STORE_NAME => 'DE',
                            MoneyValueTransfer::GROSS_AMOUNT => $expectedGrossAmount,
                            MoneyValueTransfer::NET_AMOUNT => $expectedNetAmount,
                        ],
                    ],
                ],
            ]
        );

        // Act
        $this->tester->enablePropelInstancePooling(); // JoinWith needs it to populate all 3rd level joinWith records
        $actualProductOptionValue = $this->createProductOptionFacade()->getProductOptionValueById(
            $productOptionGroupTransfer->getProductOptionValues()[0]->getIdProductOptionValue()
        );

        // Assert
        $this->assertEquals($expectedGrossAmount, $actualProductOptionValue->getUnitGrossPrice());
        $this->assertEquals($expectedNetAmount, $actualProductOptionValue->getUnitNetPrice());
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueByIdReturnsDefaultStorePricesWhenPriceNotFoundForCurrentCurrency()
    {
        // Assign
        $expectedGrossAmount = 1144;
        $expectedNetAmount = 2233;

        $this->mockStoreFacadeDefaultStore('DE');
        $this->mockCurrencyFacadeDefaultCurrency('USD');

        $productOptionGroupTransfer = $this->tester->haveProductOptionGroupWithValues(
            [],
            [
                [
                    [],
                    [
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'EUR',
                            ProductOptionGroupDataHelper::STORE_NAME => 'DE',
                        ],
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'USD',
                            ProductOptionGroupDataHelper::STORE_NAME => null,
                            MoneyValueTransfer::GROSS_AMOUNT => $expectedGrossAmount,
                            MoneyValueTransfer::NET_AMOUNT => $expectedNetAmount,
                        ],
                    ],
                ],
            ]
        );

        // Act
        $this->tester->enablePropelInstancePooling(); // JoinWith needs it to populate all 3rd level joinWith records
        $actualProductOptionValue = $this->createProductOptionFacade()->getProductOptionValueById(
            $productOptionGroupTransfer->getProductOptionValues()[0]->getIdProductOptionValue()
        );

        // Assert
        $this->assertEquals($expectedGrossAmount, $actualProductOptionValue->getUnitGrossPrice());
        $this->assertEquals($expectedNetAmount, $actualProductOptionValue->getUnitNetPrice());
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueByIdReturnsMixedPricesWhenPricesAreNotFullyDefined()
    {
        // Assign
        $expectedGrossAmount = 1144;
        $expectedNetAmount = 2233;

        $this->mockStoreFacadeDefaultStore('DE');
        $this->mockCurrencyFacadeDefaultCurrency('USD');

        $productOptionGroupTransfer = $this->tester->haveProductOptionGroupWithValues(
            [],
            [
                [
                    [],
                    [
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'USD',
                            ProductOptionGroupDataHelper::STORE_NAME => 'DE',
                            MoneyValueTransfer::GROSS_AMOUNT => null,
                            MoneyValueTransfer::NET_AMOUNT => $expectedNetAmount,
                        ],
                        [
                            ProductOptionGroupDataHelper::CURRENCY_CODE => 'USD',
                            ProductOptionGroupDataHelper::STORE_NAME => null,
                            MoneyValueTransfer::GROSS_AMOUNT => $expectedGrossAmount,
                            MoneyValueTransfer::NET_AMOUNT => null,
                        ],
                    ],
                ],
            ]
        );

        // Act
        $this->tester->enablePropelInstancePooling(); // JoinWith needs it to populate all 3rd level joinWith records
        $actualProductOptionValue = $this->createProductOptionFacade()->getProductOptionValueById(
            $productOptionGroupTransfer->getProductOptionValues()[0]->getIdProductOptionValue()
        );

        // Assert
        $this->assertEquals($expectedGrossAmount, $actualProductOptionValue->getUnitGrossPrice());
        $this->assertEquals($expectedNetAmount, $actualProductOptionValue->getUnitNetPrice());
    }

    /**
     * @return void
     */
    public function testCalculateTaxRateForProductOptionShouldSetRateToProvidedOptions()
    {
        $iso2Code = 'DE';
        $taxRate = 19;

        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $taxSetEntity = $this->tester->createTaxSet($iso2Code, $taxRate);

        $productOptionGroupTransfer->setFkTaxSet($taxSetEntity->getIdTaxSet());

        $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $quoteTransfer = new QuoteTransfer();
        $quoteTransfer->setShippingAddress($this->tester->createAddressTransfer($iso2Code));

        $productOptionTransfer = new ProductOptionTransfer();
        $productOptionTransfer->setIdProductOptionValue($productOptionValueTransfer->getIdProductOptionValue());

        $itemTransfer = new ItemTransfer();
        $itemTransfer->addProductOption($productOptionTransfer);

        $quoteTransfer->addItem($itemTransfer);

        $productOptionFacade->calculateProductOptionTaxRate($quoteTransfer);

        $itemTransfer = $quoteTransfer->getItems()[0];
        $productOptionTransfer = $itemTransfer->getProductOptions()[0];

        $this->assertEquals($taxRate, $productOptionTransfer->getTaxRate());
    }

    /**
     * @return void
     */
    public function testToggleOptionActiveShouldActivateDeactiveOptionAcordingly()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $idOfPersistedOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $productOptionFacade->toggleOptionActive($idOfPersistedOptionGroup, 1);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfPersistedOptionGroup);

        $this->assertTrue($productOptionGroupEntity->getActive());

        $productOptionFacade->toggleOptionActive($idOfPersistedOptionGroup, 0);

        $productOptionGroupEntity = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfPersistedOptionGroup);

        $this->assertFalse($productOptionGroupEntity->getActive());
    }

    /**
     * @return void
     */
    public function testProductAbstractToProductOptionGroupShouldAddNewProductToGroup()
    {
        $productOptionFacade = $this->createProductOptionFacade();

        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionGroupTransfer = $this->createProductOptionGroupTransfer($productOptionValueTransfer);
        $productOptionGroupTransfer->addProductOptionValue($productOptionValueTransfer);

        $idOfPersistedOptionGroup = $productOptionFacade->saveProductOptionGroup($productOptionGroupTransfer);

        $testSku = 'testing-sku';
        $productAbstractEntity = $this->tester->createProductAbstract($testSku);

        $productOptionFacade->addProductAbstractToProductOptionGroup(
            $productAbstractEntity->getSku(),
            $idOfPersistedOptionGroup
        );

        $groupProducts = SpyProductOptionGroupQuery::create()
            ->findOneByIdProductOptionGroup($idOfPersistedOptionGroup);

        $assignedAbstractProducts = $groupProducts->getSpyProductAbstracts();

        $this->assertEquals($assignedAbstractProducts[0]->getSku(), $productAbstractEntity->getSku());
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueStorePricesReturnsFormattedPrices()
    {
        // Assign
        $idCurrentStore = $this->getCurrentIdStore();
        $prices = new ArrayObject();
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(93)
                ->setFkStore($idCurrentStore)
                ->setGrossAmount(100)
                ->setNetAmount(200)
        );
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(250)
                ->setFkStore($idCurrentStore)
                ->setGrossAmount(300)
                ->setNetAmount(400)
        );
        $request = (new ProductOptionValueStorePricesRequestTransfer())->setPrices($prices);
        $expectedResult = [
            'EUR' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 100],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 200],
            ],
            'USD' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 300],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 400],
            ],
        ];

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionValueStorePrices($request)->getStorePrices();

        // Assert
        $this->assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueStorePricesReturnsDefaultStoreCurrencyWhenCurrencyNotExistsInCurrentStore()
    {
        // Assign
        $idCurrentStore = $this->getCurrentIdStore();
        $prices = new ArrayObject();
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(93)
                ->setFkStore($idCurrentStore)
                ->setGrossAmount(100)
                ->setNetAmount(200)
        );
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(250)
                ->setFkStore(static::DEFAULT_ID_STORE)
                ->setGrossAmount(300)
                ->setNetAmount(400)
        );
        $request = (new ProductOptionValueStorePricesRequestTransfer())->setPrices($prices);
        $expectedResult = [
            'EUR' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 100],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 200],
            ],
            'USD' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 300],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 400],
            ],
        ];

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionValueStorePrices($request)->getStorePrices();

        // Assert
        $this->assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return void
     */
    public function testGetProductOptionValueStorePricesReturnsADefaultStorePriceWhenACurrencyPriceIsNull()
    {
        // Assign
        $idCurrentStore = $this->getCurrentIdStore();
        $prices = new ArrayObject();
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(93)
                ->setFkStore($idCurrentStore)
                ->setGrossAmount(100)
                ->setNetAmount(null)
        );
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(250)
                ->setFkStore($idCurrentStore)
                ->setGrossAmount(null)
                ->setNetAmount(400)
        );
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(93)
                ->setFkStore(static::DEFAULT_ID_STORE)
                ->setGrossAmount(500)
                ->setNetAmount(600)
        );
        $prices->append(
            (new MoneyValueTransfer())
                ->setFkCurrency(250)
                ->setFkStore(static::DEFAULT_ID_STORE)
                ->setGrossAmount(700)
                ->setNetAmount(800)
        );
        $request = (new ProductOptionValueStorePricesRequestTransfer())->setPrices($prices);
        $expectedResult = [
            'EUR' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 100],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 600],
            ],
            'USD' => [
                PriceConfig::PRICE_MODE_GROSS => [ProductOptionConstants::AMOUNT => 700],
                PriceConfig::PRICE_MODE_NET => [ProductOptionConstants::AMOUNT => 400],
            ],
        ];

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionValueStorePrices($request)->getStorePrices();

        // Assert
        $this->assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return void
     */
    public function testGetProductOptionCollectionByCriteriaWithOneIdReturnsCollection(): void
    {
        $productOptionFacade = $this->createProductOptionFacade();
        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionValueTransfer->setFkProductOptionGroup($this->tester->haveProductOptionGroup()->getIdProductOptionGroup());
        $idProductOptionValue = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        $ids = [$idProductOptionValue];
        $productOptionCriteriaTransfer = (new ProductOptionCriteriaTransfer())->setIds($ids);

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionCollectionByCriteria($productOptionCriteriaTransfer);

        // Assert
        $this->assertSame(count($ids), $actualResult->getProductOptions()->count());

        foreach ($actualResult->getProductOptions() as $productOption) {
            $this->assertTrue(in_array($productOption->getIdProductOptionValue(), $ids));
        }
    }

    /**
     * @return void
     */
    public function testGetProductOptionCollectionByCriteriaWithTwoIdsReturnsCollection(): void
    {
        $productOptionFacade = $this->createProductOptionFacade();
        $productOptionValueTransfer = $this->createProductOptionValueTransfer();
        $productOptionValueTransfer->setFkProductOptionGroup($this->tester->haveProductOptionGroup()->getIdProductOptionGroup());
        $idProductOptionValue1 = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        $productOptionValueTransfer = $this->createProductOptionValueTransfer('sku_for_testing_2');
        $productOptionValueTransfer->setFkProductOptionGroup($this->tester->haveProductOptionGroup()->getIdProductOptionGroup());
        $idProductOptionValue2 = $productOptionFacade->saveProductOptionValue($productOptionValueTransfer);

        $ids = [$idProductOptionValue1, $idProductOptionValue2];
        $productOptionCriteriaTransfer = (new ProductOptionCriteriaTransfer())->setIds($ids);

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionCollectionByCriteria($productOptionCriteriaTransfer);

        // Assert
        $this->assertSame(count($ids), $actualResult->getProductOptions()->count());

        foreach ($actualResult->getProductOptions() as $productOption) {
            $this->assertTrue(in_array($productOption->getIdProductOptionValue(), $ids));
        }
    }

    /**
     * @return void
     */
    public function testGetProductOptionCollectionByCriteriaWithNoIdReturnsEmptyCollection(): void
    {
        $ids = [];
        $productOptionCriteriaTransfer = (new ProductOptionCriteriaTransfer())->setIds($ids);

        // Act
        $actualResult = $this->createProductOptionFacade()->getProductOptionCollectionByCriteria($productOptionCriteriaTransfer);

        // Assert
        $this->assertSame(count($ids), $actualResult->getProductOptions()->count());
    }

    /**
     * @return int
     */
    protected function getCurrentIdStore()
    {
        return $this->tester->getLocator()->store()->facade()->getCurrentStore()->getIdStore();
    }

    /**
     * @param \Generated\Shared\Transfer\ProductOptionValueTransfer|null $productOptionValueTransfer
     *
     * @return \Generated\Shared\Transfer\ProductOptionGroupTransfer
     */
    protected function createProductOptionGroupTransfer(?ProductOptionValueTransfer $productOptionValueTransfer = null)
    {
        $productOptionGroupTransfer = new ProductOptionGroupTransfer();
        $productOptionGroupTransfer->setName('translation.key');
        $productOptionGroupTransfer->setActive(true);

        $groupNameTranslationTransfer = new ProductOptionTranslationTransfer();
        $groupNameTranslationTransfer->setKey($productOptionGroupTransfer->getName());
        $groupNameTranslationTransfer->setLocaleCode(self::DEFAULT_LOCALE_ISO_CODE);
        $groupNameTranslationTransfer->setName('Translation1');
        $productOptionGroupTransfer->addGroupNameTranslation($groupNameTranslationTransfer);

        if ($productOptionValueTransfer) {
            $productOptionTranslationTransfer = clone $groupNameTranslationTransfer;
            $productOptionTranslationTransfer->setKey($productOptionValueTransfer->getValue());
            $productOptionTranslationTransfer->setName('value translation');
            $productOptionTranslationTransfer->setLocaleCode(self::DEFAULT_LOCALE_ISO_CODE);
            $productOptionGroupTransfer->addProductOptionValueTranslation($productOptionTranslationTransfer);
        }

        return $productOptionGroupTransfer;
    }

    /**
     * @param string $sku
     *
     * @return \Generated\Shared\Transfer\ProductOptionValueTransfer
     */
    protected function createProductOptionValueTransfer(string $sku = 'sku_for_testing'): ProductOptionValueTransfer
    {
        $productOptionValueTransfer = new ProductOptionValueTransfer();
        $productOptionValueTransfer->setValue('value.translation.key');
        $productOptionValueTransfer->setPrices(new ArrayObject());
        $productOptionValueTransfer->setSku($sku);

        $this->tester->addPrice(
            $productOptionValueTransfer,
            static::DEFAULT_ID_STORE,
            static::DEFAULT_ID_CURRENCY,
            static::DEFAULT_NET_PRICE,
            static::DEFAULT_GROSS_PRICE
        );

        return $productOptionValueTransfer;
    }

    /**
     * @return \Spryker\Zed\ProductOption\Business\ProductOptionFacade
     */
    protected function createProductOptionFacade()
    {
        $productOptionFacade = new ProductOptionFacade();

        return $productOptionFacade;
    }

    /**
     * @uses StoreFacadeInterface::getCurrentStore()
     *
     * @param string $storeName
     *
     * @return void
     */
    protected function mockStoreFacadeDefaultStore($storeName)
    {
        $storeTransfer = $this->tester->getLocator()->store()->facade()->getStoreByName($storeName);

        $storeFacadeMock = $this->getMockBuilder(StoreFacade::class)
            ->setMethods(['getCurrentStore'])
            ->getMock();

        $storeFacadeMock
            ->expects($this->any())
            ->method('getCurrentStore')
            ->willReturn($storeTransfer);

        $this->tester->setDependencyStoreFacade($storeFacadeMock);
    }

    /**
     * @uses CurrencyFacadeInterface::getCurrent()
     * @uses CurrencyFacadeInterface::fromIsoCode()
     *
     * @param string $currencyCode
     *
     * @return void
     */
    protected function mockCurrencyFacadeDefaultCurrency($currencyCode)
    {
        $currencyTransfer = $this->tester->getLocator()->currency()->facade()->fromIsoCode($currencyCode);

        $currencyFacadeMock = $this->getMockBuilder(CurrencyFacade::class)
            ->setMethods(['getCurrent', 'fromIsoCode'])
            ->getMock();

        $currencyFacadeMock
            ->expects($this->any())
            ->method('getCurrent')
            ->willReturn($currencyTransfer);

        $currencyFacadeMock
            ->expects($this->any())
            ->method('fromIsoCode')
            ->willReturn($currencyTransfer);

        $this->tester->setDependencyCurrencyFacade($currencyFacadeMock);
    }
}

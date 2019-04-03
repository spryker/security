<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\PriceProduct\Business;

use ArrayObject;
use Codeception\Test\Unit;
use Generated\Shared\DataBuilder\PriceProductFilterBuilder;
use Generated\Shared\Transfer\CurrencyTransfer;
use Generated\Shared\Transfer\MoneyValueTransfer;
use Generated\Shared\Transfer\PriceProductCriteriaTransfer;
use Generated\Shared\Transfer\PriceProductDimensionTransfer;
use Generated\Shared\Transfer\PriceProductFilterTransfer;
use Generated\Shared\Transfer\PriceProductTransfer;
use Generated\Shared\Transfer\PriceTypeTransfer;
use Generated\Shared\Transfer\ProductAbstractTransfer;
use Generated\Shared\Transfer\ProductConcreteTransfer;
use Generated\Shared\Transfer\StoreTransfer;
use Spryker\Shared\Price\PriceConfig;
use Spryker\Shared\PriceProduct\PriceProductConfig;
use Spryker\Zed\Currency\Business\CurrencyFacade;
use Spryker\Zed\PriceProduct\Business\PriceProductBusinessFactory;
use Spryker\Zed\PriceProduct\Business\PriceProductFacade;
use Spryker\Zed\PriceProduct\Communication\Plugin\DefaultPriceQueryCriteriaPlugin;
use Spryker\Zed\PriceProduct\Persistence\PriceProductEntityManager;
use Spryker\Zed\PriceProduct\PriceProductDependencyProvider;
use Spryker\Zed\Store\Business\StoreFacade;

/**
 * Auto-generated group annotations
 *
 * @group SprykerTest
 * @group Zed
 * @group PriceProduct
 * @group Business
 * @group Facade
 * @group PriceProductFacadeTest
 * Add your own group annotations below this line
 */
class PriceProductFacadeTest extends Unit
{
    public const EUR_ISO_CODE = 'EUR';
    public const USD_ISO_CODE = 'USD';
    /**
     * @var \SprykerTest\Zed\PriceProduct\PriceProductBusinessTester
     */
    protected $tester;

    /**
     * @return void
     */
    public function setUp(): void
    {
        parent::setUp();

        $priceDimensionQueryCriteriaPlugins = [
            new DefaultPriceQueryCriteriaPlugin(),
        ];

        $this->tester->setDependency(PriceProductDependencyProvider::PLUGIN_PRICE_DIMENSION_QUERY_CRITERIA, $priceDimensionQueryCriteriaPlugins);
    }

    /**
     * @return void
     */
    public function testGetPriceTypeValuesShouldReturnListOfAllPersistedPriceTypes()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypesBefore = $priceProductFacade->getPriceTypeValues();

        $priceProductFacade->createPriceType('test');

        $priceTypesAfter = $priceProductFacade->getPriceTypeValues();

        $this->assertCount(count($priceTypesBefore) + 1, $priceTypesAfter);
    }

    /**
     * @return void
     */
    public function testGetPriceBySkuShouldReturnDefaultPriceForGivenProduct()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);

        $price = $priceProductFacade->findPriceBySku($priceProductTransfer->getSkuProduct());

        $this->assertSame(50, $price);
    }

    /**
     * @return void
     */
    public function testGetPriceForShouldReturnPriceBasedOnFilter()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(
            100,
            90,
            '',
            '',
            self::USD_ISO_CODE
        );

        $priceProductFilterTransfer = (new PriceProductFilterTransfer())
            ->setCurrencyIsoCode(self::USD_ISO_CODE)
            ->setSku($priceProductTransfer->getSkuProduct());

        $price = $priceProductFacade->findPriceFor($priceProductFilterTransfer);

        $this->assertSame(100, $price);
    }

    /**
     * @return void
     */
    public function testCreatePriceType()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $idPriceType = $priceProductFacade->createPriceType('test price type');

        $this->assertNotEmpty($idPriceType);
    }

    /**
     * @return void
     */
    public function testSetPriceForProductShouldUpdateExistingPrice()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);

        $priceProductTransfer->getMoneyValue()->setGrossAmount(100);

        $priceProductFacade->setPriceForProduct($priceProductTransfer);

        $price = $priceProductFacade->findPriceBySku($priceProductTransfer->getSkuProduct());

        $this->assertSame(100, $price);
    }

    /**
     * @return void
     */
    public function testHasValidPriceShouldReturnTrueWhenProductHavePrices()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);

        $this->assertTrue(
            $priceProductFacade->hasValidPrice($priceProductTransfer->getSkuProduct())
        );
    }

    /**
     * @return void
     */
    public function testHasValidPriceForReturnTrueWhenProductHavePrices()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);

        $priceProductFilterTransfer = (new PriceProductFilterTransfer())
            ->setSku($priceProductTransfer->getSkuProduct());

        $this->assertTrue(
            $priceProductFacade->hasValidPriceFor($priceProductFilterTransfer)
        );
    }

    /**
     * @return void
     */
    public function testGetDefaultPriceTypeNameShouldReturnDefaultTypeName()
    {
        $priceProductFacade = $this->getPriceProductFacade();
        $this->assertNotEmpty($priceProductFacade->getDefaultPriceTypeName());
    }

    /**
     * @return void
     */
    public function testGetIdPriceProductShouldReturnIdOfPriceProductEntity()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);

        $idPriceProduct = $priceProductFacade->getIdPriceProduct(
            $priceProductTransfer->getSkuProduct(),
            $priceProductFacade->getDefaultPriceTypeName(),
            $this->createCurrencyFacade()->getCurrent()->getCode()
        );

        $this->assertSame($idPriceProduct, $priceProductTransfer->getIdPriceProduct());
    }

    /**
     * @return void
     */
    public function testPersistProductAbstractPriceCollectionShouldSavePriceCollection()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 11, 10, self::USD_ISO_CODE);

        $productAbstractTransfer = (new ProductAbstractTransfer())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setSku($productConcreteTransfer->getAbstractSku())
            ->setPrices($prices);

        $productAbstractTransfer = $priceProductFacade->persistProductAbstractPriceCollection($productAbstractTransfer);

        foreach ($productAbstractTransfer->getPrices() as $priceProductTransfer) {
            $this->assertNotEmpty($priceProductTransfer->getIdPriceProduct());
            $this->assertNotEmpty($priceProductTransfer->getMoneyValue()->getIdEntity());
        }
    }

    /**
     * @return void
     */
    public function testPersistProductConcretePriceCollectionShouldSavePriceCollection()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);

        $productConcreteTransfer->setPrices($prices);

        $productConcreteTransfer = $priceProductFacade->persistProductConcretePriceCollection($productConcreteTransfer);

        foreach ($productConcreteTransfer->getPrices() as $priceProductTransfer) {
            $this->assertNotEmpty($priceProductTransfer->getIdPriceProduct());
            $this->assertNotEmpty($priceProductTransfer->getMoneyValue()->getIdEntity());
        }
    }

    /**
     * @return void
     */
    public function testPriceFindPricesBySkuShouldReturnPricesForCurrentStoreConfiguration()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::USD_ISO_CODE);

        $productConcreteTransfer->setPrices($prices);

        $productConcreteTransfer = $priceProductFacade->persistProductConcretePriceCollection($productConcreteTransfer);

        $storePrices = $priceProductFacade->findPricesBySkuForCurrentStore($productConcreteTransfer->getSku());

        $this->assertCount(2, $storePrices);
    }

    /**
     * @return void
     */
    public function testFindPricesBySkuGroupedShouldReturnGroupedPrices()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $defaultPriceMode = $priceProductFacade->getDefaultPriceTypeName();
        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($defaultPriceMode);

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::USD_ISO_CODE);

        $productConcreteTransfer->setPrices($prices);

        $productConcreteTransfer = $priceProductFacade->persistProductConcretePriceCollection($productConcreteTransfer);

        $storePrices = $priceProductFacade->findPricesBySkuGroupedForCurrentStore($productConcreteTransfer->getSku());

        $this->assertCount(2, $storePrices);

        $this->assertArrayHasKey(static::EUR_ISO_CODE, $storePrices);
        $this->assertArrayHasKey(static::USD_ISO_CODE, $storePrices);

        $this->assertArrayHasKey(PriceConfig::PRICE_MODE_GROSS, $storePrices[static::EUR_ISO_CODE]);
        $this->assertArrayHasKey(PriceConfig::PRICE_MODE_NET, $storePrices[static::EUR_ISO_CODE]);
        $this->assertArrayHasKey(PriceConfig::PRICE_MODE_GROSS, $storePrices[static::USD_ISO_CODE]);
        $this->assertArrayHasKey(PriceConfig::PRICE_MODE_NET, $storePrices[static::USD_ISO_CODE]);

        $this->assertArrayHasKey($defaultPriceMode, $storePrices[static::USD_ISO_CODE][PriceConfig::PRICE_MODE_GROSS]);
        $this->assertArrayHasKey($defaultPriceMode, $storePrices[static::USD_ISO_CODE][PriceConfig::PRICE_MODE_NET]);

        $priceGross = $storePrices[static::USD_ISO_CODE][PriceConfig::PRICE_MODE_GROSS][$defaultPriceMode];
        $priceNet = $storePrices[static::USD_ISO_CODE][PriceConfig::PRICE_MODE_NET][$defaultPriceMode];

        $this->assertSame(9, $priceGross);
        $this->assertSame(10, $priceNet);
    }

    /**
     * @return void
     */
    public function testFindProductAbstractPricesShouldReturnPriceAssignedToAbstractProduct()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 11, 10, self::USD_ISO_CODE);

        $productAbstractTransfer = (new ProductAbstractTransfer())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setSku($productConcreteTransfer->getAbstractSku())
            ->setPrices($prices);

        $productAbstractTransfer = $priceProductFacade->persistProductAbstractPriceCollection($productAbstractTransfer);

        $storedPrices = $priceProductFacade->findProductAbstractPrices(
            $productAbstractTransfer->getIdProductAbstract(),
            $this->createPriceProductCriteriaTransfer()
        );

        $this->assertCount(2, $storedPrices);
    }

    /**
     * @return void
     */
    public function testFindProductConcretePricesShouldReturnPriceAssignedToConcreteProduct()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);

        $productConcreteTransfer->setPrices($prices);

        $productConcreteTransfer = $priceProductFacade->persistProductConcretePriceCollection($productConcreteTransfer);

        $storedPrices = $priceProductFacade->findProductConcretePrices(
            $productConcreteTransfer->getIdProductConcrete(),
            $productConcreteTransfer->getFkProductAbstract(),
            $this->createPriceProductCriteriaTransfer()
        );

        $this->assertCount(1, $storedPrices);
    }

    /**
     * @return void
     */
    public function testFindProductAbstractPriceShouldReturnDefaultPriceForAbstractProduct()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 11, 10, self::USD_ISO_CODE);

        $productAbstractTransfer = (new ProductAbstractTransfer())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setSku($productConcreteTransfer->getAbstractSku())
            ->setPrices($prices);

        $productAbstractTransfer = $priceProductFacade->persistProductAbstractPriceCollection($productAbstractTransfer);

        $priceProductTransfer = $priceProductFacade->findProductAbstractPrice($productAbstractTransfer->getIdProductAbstract());

        $this->assertSame(9, $priceProductTransfer->getMoneyValue()->getGrossAmount());
        $this->assertSame(10, $priceProductTransfer->getMoneyValue()->getNetAmount());
    }

    /**
     * @return void
     */
    public function testGroupPriceProductCollectionGroupsProvidedCollection()
    {
        // Assign
        $priceProductFacade = $this->getPriceProductFacade();
        $expectedResult = [
            'dummy currency 1' => [
                'GROSS_MODE' => [
                    'dummy price type 1' => 100,
                    'dummy price type 2' => 1100,
                ],
                'NET_MODE' => [
                    'dummy price type 1' => 300,
                    'dummy price type 2' => 1300,
                ],
                'priceData' => null,
            ],
            'dummy currency 2' => [
                'GROSS_MODE' => [
                    'dummy price type 1' => 200,
                    'dummy price type 2' => 1200,
                ],
                'NET_MODE' => [
                    'dummy price type 1' => 400,
                    'dummy price type 2' => 1400,
                ],
                'priceData' => null,
            ],
        ];
        $priceProductCollection = [];
        $priceProductCollection[] = $this->createPriceProduct('dummy currency 1', 'dummy price type 1', 100, 300);
        $priceProductCollection[] = $this->createPriceProduct('dummy currency 1', 'dummy price type 2', 1100, 1300);
        $priceProductCollection[] = $this->createPriceProduct('dummy currency 2', 'dummy price type 1', 200, 400);
        $priceProductCollection[] = $this->createPriceProduct('dummy currency 2', 'dummy price type 2', 1200, 1400);

        // Act
        $actualResult = $priceProductFacade->groupPriceProductCollection($priceProductCollection);

        // Assert
        $this->assertEquals($expectedResult, $actualResult);
    }

    /**
     * @return void
     */
    public function testGroupPriceProductCollectionDoesNotOverwritePriceDataByNull(): void
    {
        // Assign
        $priceProductFacade = $this->getPriceProductFacade();

        $expectedPriceData = 'dummy price data';

        $priceProductWithPriceData = $this->createPriceProduct('dummy currency 1', 'dummy price type 1', 100, 300);
        $priceProductWithPriceData->getMoneyValue()->setPriceData($expectedPriceData);

        $priceProductCollection = [];
        $priceProductCollection[] = $priceProductWithPriceData;
        $priceProductCollection[] = $this->createPriceProduct('dummy currency 1', 'dummy price type 2', 1100, 1300);

        // Act
        $actualResult = $priceProductFacade->groupPriceProductCollection($priceProductCollection);

        // Assert
        $this->assertEquals($expectedPriceData, $actualResult['dummy currency 1']['priceData']);
    }

    /**
     * @return void
     */
    public function testGetPriceModeIdentifierForBothType()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $actualResult = $priceProductFacade->getPriceModeIdentifierForBothType();

        $this->assertEquals('BOTH', $actualResult);
    }

    /**
     * @return void
     */
    public function testGeneratePriceDataChecksum()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $actualResult = $priceProductFacade->generatePriceDataChecksum(['11', '22']);

        $this->assertEquals('3b513d6f', $actualResult);
    }

    /**
     * @return void
     */
    public function testPersistPriceProductStore()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(50, 40);
        $actualResult = $priceProductFacade->persistPriceProductStore($priceProductTransfer);

        $this->assertEquals($priceProductTransfer, $actualResult);
    }

    /**
     * @return void
     */
    public function testDeleteOrphanPriceProductStoreEntitiesNotFails()
    {
        $priceProductFacade = $this->getPriceProductFacade();
        $priceProductBusinessFactory = (new PriceProductBusinessFactory());

        /** @var \Spryker\Zed\PriceProduct\Persistence\PriceProductEntityManager $priceProductEntityManagerMock */
        $priceProductEntityManagerMock = $this->getMockBuilder(PriceProductEntityManager::class)
            ->setMethods([
                'deletePriceProductStore',
            ])
            ->getMock();

        $priceProductBusinessFactory->setEntityManager($priceProductEntityManagerMock);
        $priceProductFacade->setFactory($priceProductBusinessFactory);

        $priceProductFacade->deleteOrphanPriceProductStoreEntities();
    }

    /**
     * @return void
     */
    public function testInstallNotFails()
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductFacade->install();
    }

    /**
     * @return void
     */
    public function testFindProductAbstractPricesWithoutPriceExtractionByIdProductAbstractIn(): void
    {
        $priceProductFacade = $this->getPriceProductFacade();

        $priceTypeTransfer = new PriceTypeTransfer();
        $priceTypeTransfer->setName($priceProductFacade->getDefaultPriceTypeName());

        $productConcreteTransfer = $this->tester->haveProduct();

        $prices = new ArrayObject();
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 10, 9, self::EUR_ISO_CODE);
        $prices[] = $this->createPriceProductTransfer($productConcreteTransfer, $priceTypeTransfer, 11, 10, self::USD_ISO_CODE);

        $productAbstractTransfer = (new ProductAbstractTransfer())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setSku($productConcreteTransfer->getAbstractSku())
            ->setPrices($prices);

        $productAbstractTransfer = $priceProductFacade->persistProductAbstractPriceCollection($productAbstractTransfer);

        $foundPrices = $priceProductFacade->findProductAbstractPricesWithoutPriceExtractionByIdProductAbstractIn([$productAbstractTransfer->getIdProductAbstract()]);

        $this->assertEquals(
            count($foundPrices),
            count($prices)
        );
    }

    /**
     * @return void
     */
    public function testBuildCriteriaFromFilter(): void
    {
        $priceProductFilterTransfer = (new PriceProductFilterBuilder([
            'quantity' => rand(1, 100),
        ]))->build();

        $priceProductCriteriaTransfer = $this->getPriceProductFacade()
            ->buildCriteriaFromFilter($priceProductFilterTransfer);

        $this->assertEquals($priceProductFilterTransfer->getQuantity(), $priceProductCriteriaTransfer->getQuantity());
    }

    /**
     * @param string $currencyCode
     * @param string $priceTypeName
     * @param int $grossAmount
     * @param int $netAmount
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer
     */
    protected function createPriceProduct($currencyCode, $priceTypeName, $grossAmount, $netAmount)
    {
        return (new PriceProductTransfer())
            ->setPriceType((new PriceTypeTransfer())->setName($priceTypeName))
            ->setMoneyValue(
                (new MoneyValueTransfer())
                    ->setCurrency((new CurrencyTransfer())->setCode($currencyCode))
                    ->setGrossAmount($grossAmount)
                    ->setNetAmount($netAmount)
            );
    }

    /**
     * @param int $grossAmount
     * @param int $netAmount
     * @param string $skuAbstract
     * @param string $skuConcrete
     * @param string $currencyIsoCode
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer
     */
    protected function createProductWithAmount(
        $grossAmount,
        $netAmount,
        $skuAbstract = '',
        $skuConcrete = '',
        $currencyIsoCode = ''
    ) {

        $priceProductTransfer = (new PriceProductTransfer())
            ->setSkuProductAbstract($skuAbstract)
            ->setSkuProduct($skuConcrete);

        $config = $this->createSharedPriceProductConfig();
        $priceProductDimensionTransfer = (new PriceProductDimensionTransfer())
            ->setType($config->getPriceDimensionDefault());

        $priceProductTransfer->setPriceDimension($priceProductDimensionTransfer);

        if (!$skuAbstract || !$skuConcrete) {
            $priceProductTransfer = $this->buildProduct($priceProductTransfer);
        }

        $storeTransfer = $this->createStoreFacade()->getCurrentStore();
        $currencyTransfer = $this->getCurrencyTransfer($currencyIsoCode);

        $moneyValueTransfer = $this->createMoneyValueTransfer(
            $grossAmount,
            $netAmount,
            $storeTransfer,
            $currencyTransfer
        );

        $priceProductTransfer->setMoneyValue($moneyValueTransfer);

        return $this->getPriceProductFacade()->createPriceForProduct($priceProductTransfer);
    }

    /**
     * @return \Spryker\Zed\Kernel\Business\AbstractFacade|\Spryker\Zed\PriceProduct\Business\PriceProductFacadeInterface
     */
    protected function getPriceProductFacade()
    {
        return new PriceProductFacade();
    }

    /**
     * @return \Spryker\Zed\Store\Business\StoreFacadeInterface
     */
    protected function createStoreFacade()
    {
        return new StoreFacade();
    }

    /**
     * @return \Spryker\Zed\Currency\Business\CurrencyFacadeInterface
     */
    protected function createCurrencyFacade()
    {
        return new CurrencyFacade();
    }

    /**
     * @return \Spryker\Shared\PriceProduct\PriceProductConfig
     */
    protected function createSharedPriceProductConfig()
    {
        return new PriceProductConfig();
    }

    /**
     * @param \Generated\Shared\Transfer\ProductConcreteTransfer $productConcreteTransfer
     * @param \Generated\Shared\Transfer\PriceTypeTransfer $priceTypeTransfer
     * @param int $netPrice
     * @param int $grossPrice
     * @param string $currencyIsoCode
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer
     */
    protected function createPriceProductTransfer(
        ProductConcreteTransfer $productConcreteTransfer,
        PriceTypeTransfer $priceTypeTransfer,
        $netPrice,
        $grossPrice,
        $currencyIsoCode
    ) {
        $config = $this->createSharedPriceProductConfig();
        $priceDimensionTransfer = (new PriceProductDimensionTransfer())
            ->setType($config->getPriceDimensionDefault());

        $priceProductTransfer = (new PriceProductTransfer())
            ->setIdProduct($productConcreteTransfer->getIdProductConcrete())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setSkuProductAbstract($productConcreteTransfer->getAbstractSku())
            ->setSkuProduct($productConcreteTransfer->getSku())
            ->setPriceTypeName($this->getPriceProductFacade()->getDefaultPriceTypeName())
            ->setPriceType($priceTypeTransfer)
            ->setPriceDimension($priceDimensionTransfer);

        $currencyTransfer = $this->createCurrencyFacade()->fromIsoCode($currencyIsoCode);
        $storeTransfer = $this->createStoreFacade()->getCurrentStore();

        $moneyValueTransfer = $this->createMoneyValueTransfer(
            $grossPrice,
            $netPrice,
            $storeTransfer,
            $currencyTransfer
        );

        $priceProductTransfer->setMoneyValue($moneyValueTransfer);

        return $priceProductTransfer;
    }

    /**
     * @param string $currencyIsoCode
     *
     * @return \Generated\Shared\Transfer\CurrencyTransfer
     */
    protected function getCurrencyTransfer($currencyIsoCode)
    {
        if (!$currencyIsoCode) {
            return $this->createCurrencyFacade()->getDefaultCurrencyForCurrentStore();
        }
        return $this->createCurrencyFacade()->fromIsoCode($currencyIsoCode);
    }

    /**
     * @param int $grossAmount
     * @param int $netAmount
     * @param \Generated\Shared\Transfer\StoreTransfer $storeTransfer
     * @param \Generated\Shared\Transfer\CurrencyTransfer $currencyTransfer
     *
     * @return \Generated\Shared\Transfer\MoneyValueTransfer
     */
    protected function createMoneyValueTransfer(
        $grossAmount,
        $netAmount,
        StoreTransfer $storeTransfer,
        CurrencyTransfer $currencyTransfer
    ) {
        return (new MoneyValueTransfer())
            ->setNetAmount($netAmount)
            ->setGrossAmount($grossAmount)
            ->setFkStore($storeTransfer->getIdStore())
            ->setFkCurrency($currencyTransfer->getIdCurrency())
            ->setCurrency($currencyTransfer);
    }

    /**
     * @param \Generated\Shared\Transfer\PriceProductTransfer $priceProductTransfer
     *
     * @return \Generated\Shared\Transfer\PriceProductTransfer
     */
    protected function buildProduct(PriceProductTransfer $priceProductTransfer)
    {
        $productConcreteTransfer = $this->tester->haveProduct();
        $priceProductTransfer
            ->setSkuProductAbstract($productConcreteTransfer->getAbstractSku())
            ->setSkuProduct($productConcreteTransfer->getSku())
            ->setIdProductAbstract($productConcreteTransfer->getFkProductAbstract())
            ->setIdProduct($productConcreteTransfer->getIdProductConcrete());

        return $priceProductTransfer;
    }

    /**
     * @return \Generated\Shared\Transfer\PriceProductCriteriaTransfer
     */
    protected function createPriceProductCriteriaTransfer()
    {
        $config = $this->createSharedPriceProductConfig();
        $priceProductDimensionTransfer = (new PriceProductDimensionTransfer())
            ->setType($config->getPriceDimensionDefault());

        return (new PriceProductCriteriaTransfer())
            ->setPriceDimension($priceProductDimensionTransfer);
    }

    /**
     * @group test111
     *
     * @return void
     */
    public function testRemovePriceProductStoreShouldDeletePriceFromDatabase()
    {
        // Assign
        /** @var \Spryker\Zed\PriceProduct\Business\PriceProductFacadeInterface $priceProductFacade */
        $priceProductFacade = $this->getPriceProductFacade();

        $priceProductTransfer = $this->createProductWithAmount(
            100,
            90,
            '',
            '',
            self::EUR_ISO_CODE
        );

        // Act
        $priceProductFacade->removePriceProductStore($priceProductTransfer);

        // Assert
        $priceProductFilterTransfer = (new PriceProductFilterTransfer())
            ->setCurrencyIsoCode(self::EUR_ISO_CODE)
            ->setSku($priceProductTransfer->getSkuProduct());

        $priceProduct = $priceProductFacade->findPriceProductFor($priceProductFilterTransfer);

        $this->assertNull($priceProduct, 'Price product should be removed from db');
    }
}

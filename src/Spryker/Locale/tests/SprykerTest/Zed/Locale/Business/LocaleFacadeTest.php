<?php

/**
 * Copyright © 2016-present Spryker Systems GmbH. All rights reserved.
 * Use of this software requires acceptance of the Evaluation License Agreement. See LICENSE file.
 */

namespace SprykerTest\Zed\Locale\Business;

use Codeception\Test\Unit;
use Spryker\Shared\Kernel\Store;
use Spryker\Zed\Locale\Business\LocaleFacade;
use Spryker\Zed\Locale\Persistence\LocaleQueryContainer;

/**
 * Auto-generated group annotations
 * @group SprykerTest
 * @group Zed
 * @group Locale
 * @group Business
 * @group Facade
 * @group LocaleFacadeTest
 * Add your own group annotations below this line
 */
class LocaleFacadeTest extends Unit
{
    /**
     * @var \Spryker\Zed\Locale\Business\LocaleFacade
     */
    protected $localeFacade;

    /**
     * @var \Spryker\Zed\Locale\Persistence\LocaleQueryContainerInterface
     */
    protected $localeQueryContainer;

    /**
     * @var array
     */
    protected $availableLocales = [];

    /**
     * @var array
     */
    protected $localeNames = [];

    /**
     * @return void
     */
    protected function setUp()
    {
        parent::setUp();

        $this->localeFacade = new LocaleFacade();
        $this->localeQueryContainer = new LocaleQueryContainer();
        $this->availableLocales = Store::getInstance()->getLocales();
        $this->localeNames = $this->localeFacade->getAvailableLocales();
    }

    /**
     * @return void
     */
    public function testAvailableLocalesToBeArrayType()
    {
        $this->assertInternalType('array', $this->localeNames);
    }

    /**
     * @return void
     */
    public function testAvailableLocalesAreTheSameAsConfiguredOnes()
    {
        $this->assertSame(
            array_values($this->availableLocales),
            array_values($this->localeNames)
        );
    }

    /**
     * @return void
     */
    public function testAvailableLocalesHasDifferentIdsThanConfiguredOnes()
    {
        $this->assertNotSame(
            array_keys($this->availableLocales),
            array_keys($this->localeNames)
        );
    }
}
